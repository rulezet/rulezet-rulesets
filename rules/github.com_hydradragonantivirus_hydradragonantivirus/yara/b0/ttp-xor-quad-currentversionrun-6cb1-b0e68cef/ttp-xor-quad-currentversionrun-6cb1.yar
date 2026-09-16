rule TTP_XOR_QUAD_CurrentVersionRun_6cb1 {
  strings:
    $key_6cb1 = { 3f de [2] 1b d0 [2] 30 fc [2] 1e de [2] 0a c5 [2] 05 df [2] 1b c2 [2] 19 c3 [2] 02 c5 [2] 1e c2 [2] 02 ed }

  condition:
    any of them
}