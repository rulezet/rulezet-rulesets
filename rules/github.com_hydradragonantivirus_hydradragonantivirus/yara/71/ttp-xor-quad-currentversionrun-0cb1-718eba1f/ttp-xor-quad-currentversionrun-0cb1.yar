rule TTP_XOR_QUAD_CurrentVersionRun_0cb1 {
  strings:
    $key_0cb1 = { 5f de [2] 7b d0 [2] 50 fc [2] 7e de [2] 6a c5 [2] 65 df [2] 7b c2 [2] 79 c3 [2] 62 c5 [2] 7e c2 [2] 62 ed }

  condition:
    any of them
}