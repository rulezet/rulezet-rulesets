rule TTP_XOR_QUAD_CurrentVersionRun_8a24 {
  strings:
    $key_8a24 = { d9 4b [2] fd 45 [2] d6 69 [2] f8 4b [2] ec 50 [2] e3 4a [2] fd 57 [2] ff 56 [2] e4 50 [2] f8 57 [2] e4 78 }

  condition:
    any of them
}