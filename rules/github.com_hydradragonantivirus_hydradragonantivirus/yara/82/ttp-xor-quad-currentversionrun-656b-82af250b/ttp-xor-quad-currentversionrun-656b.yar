rule TTP_XOR_QUAD_CurrentVersionRun_656b {
  strings:
    $key_656b = { 36 04 [2] 12 0a [2] 39 26 [2] 17 04 [2] 03 1f [2] 0c 05 [2] 12 18 [2] 10 19 [2] 0b 1f [2] 17 18 [2] 0b 37 }

  condition:
    any of them
}