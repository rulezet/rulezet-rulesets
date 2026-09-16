rule TTP_XOR_QUAD_CurrentVersionRun_560b {
  strings:
    $key_560b = { 05 64 [2] 21 6a [2] 0a 46 [2] 24 64 [2] 30 7f [2] 3f 65 [2] 21 78 [2] 23 79 [2] 38 7f [2] 24 78 [2] 38 57 }

  condition:
    any of them
}