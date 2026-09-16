rule TTP_XOR_QUAD_CurrentVersionRun_8a33 {
  strings:
    $key_8a33 = { d9 5c [2] fd 52 [2] d6 7e [2] f8 5c [2] ec 47 [2] e3 5d [2] fd 40 [2] ff 41 [2] e4 47 [2] f8 40 [2] e4 6f }

  condition:
    any of them
}