rule TTP_XOR_QUAD_CurrentVersionRun_3fb1 {
  strings:
    $key_3fb1 = { 6c de [2] 48 d0 [2] 63 fc [2] 4d de [2] 59 c5 [2] 56 df [2] 48 c2 [2] 4a c3 [2] 51 c5 [2] 4d c2 [2] 51 ed }

  condition:
    any of them
}