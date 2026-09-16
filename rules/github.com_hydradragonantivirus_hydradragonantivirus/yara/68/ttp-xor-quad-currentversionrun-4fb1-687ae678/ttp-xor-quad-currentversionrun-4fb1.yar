rule TTP_XOR_QUAD_CurrentVersionRun_4fb1 {
  strings:
    $key_4fb1 = { 1c de [2] 38 d0 [2] 13 fc [2] 3d de [2] 29 c5 [2] 26 df [2] 38 c2 [2] 3a c3 [2] 21 c5 [2] 3d c2 [2] 21 ed }

  condition:
    any of them
}