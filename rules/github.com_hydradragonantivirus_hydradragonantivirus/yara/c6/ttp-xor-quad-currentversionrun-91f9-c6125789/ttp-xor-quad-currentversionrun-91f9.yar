rule TTP_XOR_QUAD_CurrentVersionRun_91f9 {
  strings:
    $key_91f9 = { c2 96 [2] e6 98 [2] cd b4 [2] e3 96 [2] f7 8d [2] f8 97 [2] e6 8a [2] e4 8b [2] ff 8d [2] e3 8a [2] ff a5 }

  condition:
    any of them
}