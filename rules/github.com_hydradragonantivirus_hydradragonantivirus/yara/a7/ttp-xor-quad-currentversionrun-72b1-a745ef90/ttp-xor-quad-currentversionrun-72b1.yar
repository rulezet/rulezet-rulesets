rule TTP_XOR_QUAD_CurrentVersionRun_72b1 {
  strings:
    $key_72b1 = { 21 de [2] 05 d0 [2] 2e fc [2] 00 de [2] 14 c5 [2] 1b df [2] 05 c2 [2] 07 c3 [2] 1c c5 [2] 00 c2 [2] 1c ed }

  condition:
    any of them
}