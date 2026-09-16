rule TTP_XOR_QUAD_CurrentVersionRun_2fb1 {
  strings:
    $key_2fb1 = { 7c de [2] 58 d0 [2] 73 fc [2] 5d de [2] 49 c5 [2] 46 df [2] 58 c2 [2] 5a c3 [2] 41 c5 [2] 5d c2 [2] 41 ed }

  condition:
    any of them
}