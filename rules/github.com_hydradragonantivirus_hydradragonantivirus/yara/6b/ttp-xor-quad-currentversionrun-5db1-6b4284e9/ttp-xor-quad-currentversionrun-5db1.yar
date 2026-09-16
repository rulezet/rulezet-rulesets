rule TTP_XOR_QUAD_CurrentVersionRun_5db1 {
  strings:
    $key_5db1 = { 0e de [2] 2a d0 [2] 01 fc [2] 2f de [2] 3b c5 [2] 34 df [2] 2a c2 [2] 28 c3 [2] 33 c5 [2] 2f c2 [2] 33 ed }

  condition:
    any of them
}