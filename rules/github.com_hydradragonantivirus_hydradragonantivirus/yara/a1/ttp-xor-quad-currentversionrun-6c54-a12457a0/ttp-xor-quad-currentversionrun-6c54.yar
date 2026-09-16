rule TTP_XOR_QUAD_CurrentVersionRun_6c54 {
  strings:
    $key_6c54 = { 3f 3b [2] 1b 35 [2] 30 19 [2] 1e 3b [2] 0a 20 [2] 05 3a [2] 1b 27 [2] 19 26 [2] 02 20 [2] 1e 27 [2] 02 08 }

  condition:
    any of them
}