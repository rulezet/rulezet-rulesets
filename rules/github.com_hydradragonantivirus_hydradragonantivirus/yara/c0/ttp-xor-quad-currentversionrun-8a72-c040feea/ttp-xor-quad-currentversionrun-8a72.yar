rule TTP_XOR_QUAD_CurrentVersionRun_8a72 {
  strings:
    $key_8a72 = { d9 1d [2] fd 13 [2] d6 3f [2] f8 1d [2] ec 06 [2] e3 1c [2] fd 01 [2] ff 00 [2] e4 06 [2] f8 01 [2] e4 2e }

  condition:
    any of them
}