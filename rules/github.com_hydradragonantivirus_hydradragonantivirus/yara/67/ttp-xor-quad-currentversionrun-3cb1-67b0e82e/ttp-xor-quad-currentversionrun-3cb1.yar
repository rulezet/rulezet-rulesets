rule TTP_XOR_QUAD_CurrentVersionRun_3cb1 {
  strings:
    $key_3cb1 = { 6f de [2] 4b d0 [2] 60 fc [2] 4e de [2] 5a c5 [2] 55 df [2] 4b c2 [2] 49 c3 [2] 52 c5 [2] 4e c2 [2] 52 ed }

  condition:
    any of them
}