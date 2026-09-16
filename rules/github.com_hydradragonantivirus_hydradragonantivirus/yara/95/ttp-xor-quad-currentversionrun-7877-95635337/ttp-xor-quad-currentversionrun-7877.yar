rule TTP_XOR_QUAD_CurrentVersionRun_7877 {
  strings:
    $key_7877 = { 2b 18 [2] 0f 16 [2] 24 3a [2] 0a 18 [2] 1e 03 [2] 11 19 [2] 0f 04 [2] 0d 05 [2] 16 03 [2] 0a 04 [2] 16 2b }

  condition:
    any of them
}