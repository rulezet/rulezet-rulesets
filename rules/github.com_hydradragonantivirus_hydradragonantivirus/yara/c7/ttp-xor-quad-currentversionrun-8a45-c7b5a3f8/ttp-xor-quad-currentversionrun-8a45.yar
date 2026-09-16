rule TTP_XOR_QUAD_CurrentVersionRun_8a45 {
  strings:
    $key_8a45 = { d9 2a [2] fd 24 [2] d6 08 [2] f8 2a [2] ec 31 [2] e3 2b [2] fd 36 [2] ff 37 [2] e4 31 [2] f8 36 [2] e4 19 }

  condition:
    any of them
}