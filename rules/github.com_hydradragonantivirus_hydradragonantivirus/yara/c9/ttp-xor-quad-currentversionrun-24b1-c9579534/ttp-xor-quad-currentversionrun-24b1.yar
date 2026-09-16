rule TTP_XOR_QUAD_CurrentVersionRun_24b1 {
  strings:
    $key_24b1 = { 77 de [2] 53 d0 [2] 78 fc [2] 56 de [2] 42 c5 [2] 4d df [2] 53 c2 [2] 51 c3 [2] 4a c5 [2] 56 c2 [2] 4a ed }

  condition:
    any of them
}