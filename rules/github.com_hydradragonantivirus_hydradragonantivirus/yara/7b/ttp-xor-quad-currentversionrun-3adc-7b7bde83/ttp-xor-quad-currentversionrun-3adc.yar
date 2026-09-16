rule TTP_XOR_QUAD_CurrentVersionRun_3adc {
  strings:
    $key_3adc = { 69 b3 [2] 4d bd [2] 66 91 [2] 48 b3 [2] 5c a8 [2] 53 b2 [2] 4d af [2] 4f ae [2] 54 a8 [2] 48 af [2] 54 80 }

  condition:
    any of them
}