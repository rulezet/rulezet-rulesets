rule TTP_XOR_QUAD_CurrentVersionRun_8a50 {
  strings:
    $key_8a50 = { d9 3f [2] fd 31 [2] d6 1d [2] f8 3f [2] ec 24 [2] e3 3e [2] fd 23 [2] ff 22 [2] e4 24 [2] f8 23 [2] e4 0c }

  condition:
    any of them
}