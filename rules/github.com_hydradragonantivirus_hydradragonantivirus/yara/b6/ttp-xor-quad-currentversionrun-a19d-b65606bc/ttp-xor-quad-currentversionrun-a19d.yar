rule TTP_XOR_QUAD_CurrentVersionRun_a19d {
  strings:
    $key_a19d = { f2 f2 [2] d6 fc [2] fd d0 [2] d3 f2 [2] c7 e9 [2] c8 f3 [2] d6 ee [2] d4 ef [2] cf e9 [2] d3 ee [2] cf c1 }

  condition:
    any of them
}