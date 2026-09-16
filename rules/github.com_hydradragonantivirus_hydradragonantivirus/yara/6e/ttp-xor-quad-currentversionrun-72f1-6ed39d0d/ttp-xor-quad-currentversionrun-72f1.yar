rule TTP_XOR_QUAD_CurrentVersionRun_72f1 {
  strings:
    $key_72f1 = { 21 9e [2] 05 90 [2] 2e bc [2] 00 9e [2] 14 85 [2] 1b 9f [2] 05 82 [2] 07 83 [2] 1c 85 [2] 00 82 [2] 1c ad }

  condition:
    any of them
}