rule TTP_XOR_QUAD_CurrentVersionRun_b702 {
  strings:
    $key_b702 = { e4 6d [2] c0 63 [2] eb 4f [2] c5 6d [2] d1 76 [2] de 6c [2] c0 71 [2] c2 70 [2] d9 76 [2] c5 71 [2] d9 5e }

  condition:
    any of them
}