rule TTP_XOR_QUAD_CurrentVersionRun_50b1 {
  strings:
    $key_50b1 = { 03 de [2] 27 d0 [2] 0c fc [2] 22 de [2] 36 c5 [2] 39 df [2] 27 c2 [2] 25 c3 [2] 3e c5 [2] 22 c2 [2] 3e ed }

  condition:
    any of them
}