rule TTP_XOR_QUAD_CurrentVersionRun_8a46 {
  strings:
    $key_8a46 = { d9 29 [2] fd 27 [2] d6 0b [2] f8 29 [2] ec 32 [2] e3 28 [2] fd 35 [2] ff 34 [2] e4 32 [2] f8 35 [2] e4 1a }

  condition:
    any of them
}