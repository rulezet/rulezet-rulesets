rule TTP_XOR_QUAD_CurrentVersionRun_6c67 {
  strings:
    $key_6c67 = { 3f 08 [2] 1b 06 [2] 30 2a [2] 1e 08 [2] 0a 13 [2] 05 09 [2] 1b 14 [2] 19 15 [2] 02 13 [2] 1e 14 [2] 02 3b }

  condition:
    any of them
}