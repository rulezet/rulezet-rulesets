rule TTP_XOR_QUAD_CurrentVersionRun_abb1 {
  strings:
    $key_abb1 = { f8 de [2] dc d0 [2] f7 fc [2] d9 de [2] cd c5 [2] c2 df [2] dc c2 [2] de c3 [2] c5 c5 [2] d9 c2 [2] c5 ed }

  condition:
    any of them
}