rule TTP_XOR_QUAD_CurrentVersionRun_1e27 {
  strings:
    $key_1e27 = { 4d 48 [2] 69 46 [2] 42 6a [2] 6c 48 [2] 78 53 [2] 77 49 [2] 69 54 [2] 6b 55 [2] 70 53 [2] 6c 54 [2] 70 7b }

  condition:
    any of them
}