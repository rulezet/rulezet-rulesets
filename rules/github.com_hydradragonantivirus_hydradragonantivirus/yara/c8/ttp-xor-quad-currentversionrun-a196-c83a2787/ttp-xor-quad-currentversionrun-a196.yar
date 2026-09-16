rule TTP_XOR_QUAD_CurrentVersionRun_a196 {
  strings:
    $key_a196 = { f2 f9 [2] d6 f7 [2] fd db [2] d3 f9 [2] c7 e2 [2] c8 f8 [2] d6 e5 [2] d4 e4 [2] cf e2 [2] d3 e5 [2] cf ca }

  condition:
    any of them
}