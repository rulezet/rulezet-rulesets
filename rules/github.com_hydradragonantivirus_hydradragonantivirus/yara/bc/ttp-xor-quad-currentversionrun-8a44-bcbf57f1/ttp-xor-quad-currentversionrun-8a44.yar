rule TTP_XOR_QUAD_CurrentVersionRun_8a44 {
  strings:
    $key_8a44 = { d9 2b [2] fd 25 [2] d6 09 [2] f8 2b [2] ec 30 [2] e3 2a [2] fd 37 [2] ff 36 [2] e4 30 [2] f8 37 [2] e4 18 }

  condition:
    any of them
}