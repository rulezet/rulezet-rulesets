rule TTP_XOR_QUAD_CurrentVersionRun_91e9 {
  strings:
    $key_91e9 = { c2 86 [2] e6 88 [2] cd a4 [2] e3 86 [2] f7 9d [2] f8 87 [2] e6 9a [2] e4 9b [2] ff 9d [2] e3 9a [2] ff b5 }

  condition:
    any of them
}