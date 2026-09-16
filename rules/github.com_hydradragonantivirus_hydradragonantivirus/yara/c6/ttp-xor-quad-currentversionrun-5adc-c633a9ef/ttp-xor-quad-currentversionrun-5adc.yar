rule TTP_XOR_QUAD_CurrentVersionRun_5adc {
  strings:
    $key_5adc = { 09 b3 [2] 2d bd [2] 06 91 [2] 28 b3 [2] 3c a8 [2] 33 b2 [2] 2d af [2] 2f ae [2] 34 a8 [2] 28 af [2] 34 80 }

  condition:
    any of them
}