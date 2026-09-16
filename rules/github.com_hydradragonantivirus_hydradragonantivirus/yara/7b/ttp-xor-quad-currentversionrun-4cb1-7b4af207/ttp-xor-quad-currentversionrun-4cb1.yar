rule TTP_XOR_QUAD_CurrentVersionRun_4cb1 {
  strings:
    $key_4cb1 = { 1f de [2] 3b d0 [2] 10 fc [2] 3e de [2] 2a c5 [2] 25 df [2] 3b c2 [2] 39 c3 [2] 22 c5 [2] 3e c2 [2] 22 ed }

  condition:
    any of them
}