rule TTP_XOR_QUAD_CurrentVersionRun_6c64 {
  strings:
    $key_6c64 = { 3f 0b [2] 1b 05 [2] 30 29 [2] 1e 0b [2] 0a 10 [2] 05 0a [2] 1b 17 [2] 19 16 [2] 02 10 [2] 1e 17 [2] 02 38 }

  condition:
    any of them
}