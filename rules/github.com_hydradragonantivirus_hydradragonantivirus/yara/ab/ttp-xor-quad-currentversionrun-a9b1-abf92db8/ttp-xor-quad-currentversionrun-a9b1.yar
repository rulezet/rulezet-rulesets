rule TTP_XOR_QUAD_CurrentVersionRun_a9b1 {
  strings:
    $key_a9b1 = { fa de [2] de d0 [2] f5 fc [2] db de [2] cf c5 [2] c0 df [2] de c2 [2] dc c3 [2] c7 c5 [2] db c2 [2] c7 ed }

  condition:
    any of them
}