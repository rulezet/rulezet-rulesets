rule TTP_XOR_QUAD_CurrentVersionRun_a4b1 {
  strings:
    $key_a4b1 = { f7 de [2] d3 d0 [2] f8 fc [2] d6 de [2] c2 c5 [2] cd df [2] d3 c2 [2] d1 c3 [2] ca c5 [2] d6 c2 [2] ca ed }

  condition:
    any of them
}