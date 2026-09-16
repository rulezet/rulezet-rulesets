rule TTP_XOR_QUAD_CurrentVersionRun_6adc {
  strings:
    $key_6adc = { 39 b3 [2] 1d bd [2] 36 91 [2] 18 b3 [2] 0c a8 [2] 03 b2 [2] 1d af [2] 1f ae [2] 04 a8 [2] 18 af [2] 04 80 }

  condition:
    any of them
}