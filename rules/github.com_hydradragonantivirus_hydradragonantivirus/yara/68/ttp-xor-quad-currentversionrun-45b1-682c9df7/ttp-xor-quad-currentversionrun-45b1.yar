rule TTP_XOR_QUAD_CurrentVersionRun_45b1 {
  strings:
    $key_45b1 = { 16 de [2] 32 d0 [2] 19 fc [2] 37 de [2] 23 c5 [2] 2c df [2] 32 c2 [2] 30 c3 [2] 2b c5 [2] 37 c2 [2] 2b ed }

  condition:
    any of them
}