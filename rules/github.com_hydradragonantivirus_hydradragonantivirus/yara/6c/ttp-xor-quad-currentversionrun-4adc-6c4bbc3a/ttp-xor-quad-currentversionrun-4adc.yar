rule TTP_XOR_QUAD_CurrentVersionRun_4adc {
  strings:
    $key_4adc = { 19 b3 [2] 3d bd [2] 16 91 [2] 38 b3 [2] 2c a8 [2] 23 b2 [2] 3d af [2] 3f ae [2] 24 a8 [2] 38 af [2] 24 80 }

  condition:
    any of them
}