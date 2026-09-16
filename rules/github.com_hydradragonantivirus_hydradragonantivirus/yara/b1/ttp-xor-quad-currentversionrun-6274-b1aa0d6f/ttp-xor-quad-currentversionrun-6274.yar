rule TTP_XOR_QUAD_CurrentVersionRun_6274 {
  strings:
    $key_6274 = { 31 1b [2] 15 15 [2] 3e 39 [2] 10 1b [2] 04 00 [2] 0b 1a [2] 15 07 [2] 17 06 [2] 0c 00 [2] 10 07 [2] 0c 28 }

  condition:
    any of them
}