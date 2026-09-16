rule TTP_XOR_QUAD_CurrentVersionRun_8a40 {
  strings:
    $key_8a40 = { d9 2f [2] fd 21 [2] d6 0d [2] f8 2f [2] ec 34 [2] e3 2e [2] fd 33 [2] ff 32 [2] e4 34 [2] f8 33 [2] e4 1c }

  condition:
    any of them
}