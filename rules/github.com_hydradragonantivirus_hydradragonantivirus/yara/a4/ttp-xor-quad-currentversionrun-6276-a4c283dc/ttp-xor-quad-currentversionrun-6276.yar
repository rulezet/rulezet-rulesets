rule TTP_XOR_QUAD_CurrentVersionRun_6276 {
  strings:
    $key_6276 = { 31 19 [2] 15 17 [2] 3e 3b [2] 10 19 [2] 04 02 [2] 0b 18 [2] 15 05 [2] 17 04 [2] 0c 02 [2] 10 05 [2] 0c 2a }

  condition:
    any of them
}