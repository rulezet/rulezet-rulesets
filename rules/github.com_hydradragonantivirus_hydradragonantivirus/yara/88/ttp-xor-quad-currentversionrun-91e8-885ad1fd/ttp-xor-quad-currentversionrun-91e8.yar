rule TTP_XOR_QUAD_CurrentVersionRun_91e8 {
  strings:
    $key_91e8 = { c2 87 [2] e6 89 [2] cd a5 [2] e3 87 [2] f7 9c [2] f8 86 [2] e6 9b [2] e4 9a [2] ff 9c [2] e3 9b [2] ff b4 }

  condition:
    any of them
}