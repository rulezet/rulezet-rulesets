rule TTP_XOR_QUAD_CurrentVersionRun_280b {
  strings:
    $key_280b = { 7b 64 [2] 5f 6a [2] 74 46 [2] 5a 64 [2] 4e 7f [2] 41 65 [2] 5f 78 [2] 5d 79 [2] 46 7f [2] 5a 78 [2] 46 57 }

  condition:
    any of them
}