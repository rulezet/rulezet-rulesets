rule TTP_XOR_QUAD_CurrentVersionRun_15b1 {
  strings:
    $key_15b1 = { 46 de [2] 62 d0 [2] 49 fc [2] 67 de [2] 73 c5 [2] 7c df [2] 62 c2 [2] 60 c3 [2] 7b c5 [2] 67 c2 [2] 7b ed }

  condition:
    any of them
}