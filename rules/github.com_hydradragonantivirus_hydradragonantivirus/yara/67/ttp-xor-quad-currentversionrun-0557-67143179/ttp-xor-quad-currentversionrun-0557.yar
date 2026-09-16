rule TTP_XOR_QUAD_CurrentVersionRun_0557 {
  strings:
    $key_0557 = { 56 38 [2] 72 36 [2] 59 1a [2] 77 38 [2] 63 23 [2] 6c 39 [2] 72 24 [2] 70 25 [2] 6b 23 [2] 77 24 [2] 6b 0b }

  condition:
    any of them
}