rule TTP_XOR_QUAD_CurrentVersionRun_91e4 {
  strings:
    $key_91e4 = { c2 8b [2] e6 85 [2] cd a9 [2] e3 8b [2] f7 90 [2] f8 8a [2] e6 97 [2] e4 96 [2] ff 90 [2] e3 97 [2] ff b8 }

  condition:
    any of them
}