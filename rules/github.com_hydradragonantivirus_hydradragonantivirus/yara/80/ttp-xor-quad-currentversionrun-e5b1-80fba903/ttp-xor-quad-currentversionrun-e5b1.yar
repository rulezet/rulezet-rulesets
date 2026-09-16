rule TTP_XOR_QUAD_CurrentVersionRun_e5b1 {
  strings:
    $key_e5b1 = { b6 de [2] 92 d0 [2] b9 fc [2] 97 de [2] 83 c5 [2] 8c df [2] 92 c2 [2] 90 c3 [2] 8b c5 [2] 97 c2 [2] 8b ed }

  condition:
    any of them
}