rule TTP_XOR_QUAD_CurrentVersionRun_1277 {
  strings:
    $key_1277 = { 41 18 [2] 65 16 [2] 4e 3a [2] 60 18 [2] 74 03 [2] 7b 19 [2] 65 04 [2] 67 05 [2] 7c 03 [2] 60 04 [2] 7c 2b }

  condition:
    any of them
}