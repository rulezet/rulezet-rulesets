rule TTP_XOR_QUAD_CurrentVersionRun_8a56 {
  strings:
    $key_8a56 = { d9 39 [2] fd 37 [2] d6 1b [2] f8 39 [2] ec 22 [2] e3 38 [2] fd 25 [2] ff 24 [2] e4 22 [2] f8 25 [2] e4 0a }

  condition:
    any of them
}