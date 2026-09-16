rule TTP_XOR_QUAD_CurrentVersionRun_b0c2 {
  strings:
    $key_b0c2 = { e3 ad [2] c7 a3 [2] ec 8f [2] c2 ad [2] d6 b6 [2] d9 ac [2] c7 b1 [2] c5 b0 [2] de b6 [2] c2 b1 [2] de 9e }

  condition:
    any of them
}