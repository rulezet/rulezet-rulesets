rule TTP_XOR_QUAD_CurrentVersionRun_0fb1 {
  strings:
    $key_0fb1 = { 5c de [2] 78 d0 [2] 53 fc [2] 7d de [2] 69 c5 [2] 66 df [2] 78 c2 [2] 7a c3 [2] 61 c5 [2] 7d c2 [2] 61 ed }

  condition:
    any of them
}