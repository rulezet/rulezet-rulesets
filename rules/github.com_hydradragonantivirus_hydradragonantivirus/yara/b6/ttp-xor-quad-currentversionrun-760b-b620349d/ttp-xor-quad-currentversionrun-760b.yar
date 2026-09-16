rule TTP_XOR_QUAD_CurrentVersionRun_760b {
  strings:
    $key_760b = { 25 64 [2] 01 6a [2] 2a 46 [2] 04 64 [2] 10 7f [2] 1f 65 [2] 01 78 [2] 03 79 [2] 18 7f [2] 04 78 [2] 18 57 }

  condition:
    any of them
}