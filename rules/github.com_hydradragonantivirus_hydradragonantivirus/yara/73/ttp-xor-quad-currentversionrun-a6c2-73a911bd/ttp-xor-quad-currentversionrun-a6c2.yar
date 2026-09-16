rule TTP_XOR_QUAD_CurrentVersionRun_a6c2 {
  strings:
    $key_a6c2 = { f5 ad [2] d1 a3 [2] fa 8f [2] d4 ad [2] c0 b6 [2] cf ac [2] d1 b1 [2] d3 b0 [2] c8 b6 [2] d4 b1 [2] c8 9e }

  condition:
    any of them
}