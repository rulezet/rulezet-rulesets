rule TTP_XOR_QUAD_CurrentVersionRun_30b1 {
  strings:
    $key_30b1 = { 63 de [2] 47 d0 [2] 6c fc [2] 42 de [2] 56 c5 [2] 59 df [2] 47 c2 [2] 45 c3 [2] 5e c5 [2] 42 c2 [2] 5e ed }

  condition:
    any of them
}