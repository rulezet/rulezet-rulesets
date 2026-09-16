rule TTP_XOR_QUAD_CurrentVersionRun_3877 {
  strings:
    $key_3877 = { 6b 18 [2] 4f 16 [2] 64 3a [2] 4a 18 [2] 5e 03 [2] 51 19 [2] 4f 04 [2] 4d 05 [2] 56 03 [2] 4a 04 [2] 56 2b }

  condition:
    any of them
}