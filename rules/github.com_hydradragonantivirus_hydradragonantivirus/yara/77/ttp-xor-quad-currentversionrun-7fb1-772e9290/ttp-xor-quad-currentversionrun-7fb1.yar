rule TTP_XOR_QUAD_CurrentVersionRun_7fb1 {
  strings:
    $key_7fb1 = { 2c de [2] 08 d0 [2] 23 fc [2] 0d de [2] 19 c5 [2] 16 df [2] 08 c2 [2] 0a c3 [2] 11 c5 [2] 0d c2 [2] 11 ed }

  condition:
    any of them
}