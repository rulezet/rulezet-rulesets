rule TTP_XOR_QUAD_CurrentVersionRun_4966 {
  strings:
    $key_4966 = { 1a 09 [2] 3e 07 [2] 15 2b [2] 3b 09 [2] 2f 12 [2] 20 08 [2] 3e 15 [2] 3c 14 [2] 27 12 [2] 3b 15 [2] 27 3a }

  condition:
    any of them
}