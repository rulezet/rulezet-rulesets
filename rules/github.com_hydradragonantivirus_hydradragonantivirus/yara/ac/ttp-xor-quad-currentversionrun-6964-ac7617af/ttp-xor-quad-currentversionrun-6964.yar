rule TTP_XOR_QUAD_CurrentVersionRun_6964 {
  strings:
    $key_6964 = { 3a 0b [2] 1e 05 [2] 35 29 [2] 1b 0b [2] 0f 10 [2] 00 0a [2] 1e 17 [2] 1c 16 [2] 07 10 [2] 1b 17 [2] 07 38 }

  condition:
    any of them
}