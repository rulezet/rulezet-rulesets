rule TTP_XOR_QUAD_CurrentVersionRun_35b1 {
  strings:
    $key_35b1 = { 66 de [2] 42 d0 [2] 69 fc [2] 47 de [2] 53 c5 [2] 5c df [2] 42 c2 [2] 40 c3 [2] 5b c5 [2] 47 c2 [2] 5b ed }

  condition:
    any of them
}