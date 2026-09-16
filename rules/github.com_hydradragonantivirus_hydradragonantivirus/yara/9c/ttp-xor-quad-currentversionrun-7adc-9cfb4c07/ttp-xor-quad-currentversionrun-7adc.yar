rule TTP_XOR_QUAD_CurrentVersionRun_7adc {
  strings:
    $key_7adc = { 29 b3 [2] 0d bd [2] 26 91 [2] 08 b3 [2] 1c a8 [2] 13 b2 [2] 0d af [2] 0f ae [2] 14 a8 [2] 08 af [2] 14 80 }

  condition:
    any of them
}