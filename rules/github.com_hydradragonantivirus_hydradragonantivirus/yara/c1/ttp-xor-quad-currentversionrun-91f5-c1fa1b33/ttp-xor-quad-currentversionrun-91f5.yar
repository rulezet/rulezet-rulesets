rule TTP_XOR_QUAD_CurrentVersionRun_91f5 {
  strings:
    $key_91f5 = { c2 9a [2] e6 94 [2] cd b8 [2] e3 9a [2] f7 81 [2] f8 9b [2] e6 86 [2] e4 87 [2] ff 81 [2] e3 86 [2] ff a9 }

  condition:
    any of them
}