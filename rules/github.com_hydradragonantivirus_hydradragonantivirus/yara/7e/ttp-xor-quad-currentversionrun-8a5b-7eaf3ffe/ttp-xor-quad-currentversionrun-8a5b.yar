rule TTP_XOR_QUAD_CurrentVersionRun_8a5b {
  strings:
    $key_8a5b = { d9 34 [2] fd 3a [2] d6 16 [2] f8 34 [2] ec 2f [2] e3 35 [2] fd 28 [2] ff 29 [2] e4 2f [2] f8 28 [2] e4 07 }

  condition:
    any of them
}