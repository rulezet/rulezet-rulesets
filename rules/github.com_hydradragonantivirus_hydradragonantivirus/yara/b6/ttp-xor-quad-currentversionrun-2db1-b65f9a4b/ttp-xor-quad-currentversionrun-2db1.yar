rule TTP_XOR_QUAD_CurrentVersionRun_2db1 {
  strings:
    $key_2db1 = { 7e de [2] 5a d0 [2] 71 fc [2] 5f de [2] 4b c5 [2] 44 df [2] 5a c2 [2] 58 c3 [2] 43 c5 [2] 5f c2 [2] 43 ed }

  condition:
    any of them
}