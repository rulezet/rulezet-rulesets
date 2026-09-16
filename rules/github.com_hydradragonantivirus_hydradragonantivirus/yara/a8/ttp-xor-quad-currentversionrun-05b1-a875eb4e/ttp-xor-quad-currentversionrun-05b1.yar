rule TTP_XOR_QUAD_CurrentVersionRun_05b1 {
  strings:
    $key_05b1 = { 56 de [2] 72 d0 [2] 59 fc [2] 77 de [2] 63 c5 [2] 6c df [2] 72 c2 [2] 70 c3 [2] 6b c5 [2] 77 c2 [2] 6b ed }

  condition:
    any of them
}