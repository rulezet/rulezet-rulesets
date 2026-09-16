rule TTP_XOR_QUAD_CurrentVersionRun_8a04 {
  strings:
    $key_8a04 = { d9 6b [2] fd 65 [2] d6 49 [2] f8 6b [2] ec 70 [2] e3 6a [2] fd 77 [2] ff 76 [2] e4 70 [2] f8 77 [2] e4 58 }

  condition:
    any of them
}