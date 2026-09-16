rule TTP_XOR_QUAD_CurrentVersionRun_dfb1 {
  strings:
    $key_dfb1 = { 8c de [2] a8 d0 [2] 83 fc [2] ad de [2] b9 c5 [2] b6 df [2] a8 c2 [2] aa c3 [2] b1 c5 [2] ad c2 [2] b1 ed }

  condition:
    any of them
}