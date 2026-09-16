rule TTP_XOR_QUAD_CurrentVersionRun_b402 {
  strings:
    $key_b402 = { e7 6d [2] c3 63 [2] e8 4f [2] c6 6d [2] d2 76 [2] dd 6c [2] c3 71 [2] c1 70 [2] da 76 [2] c6 71 [2] da 5e }

  condition:
    any of them
}