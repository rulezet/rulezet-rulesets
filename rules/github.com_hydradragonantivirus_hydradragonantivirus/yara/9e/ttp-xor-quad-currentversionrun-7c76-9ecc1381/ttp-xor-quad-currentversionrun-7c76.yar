rule TTP_XOR_QUAD_CurrentVersionRun_7c76 {
  strings:
    $key_7c76 = { 2f 19 [2] 0b 17 [2] 20 3b [2] 0e 19 [2] 1a 02 [2] 15 18 [2] 0b 05 [2] 09 04 [2] 12 02 [2] 0e 05 [2] 12 2a }

  condition:
    any of them
}