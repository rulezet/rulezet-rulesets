rule TTP_XOR_QUAD_CurrentVersionRun_34b1 {
  strings:
    $key_34b1 = { 67 de [2] 43 d0 [2] 68 fc [2] 46 de [2] 52 c5 [2] 5d df [2] 43 c2 [2] 41 c3 [2] 5a c5 [2] 46 c2 [2] 5a ed }

  condition:
    any of them
}