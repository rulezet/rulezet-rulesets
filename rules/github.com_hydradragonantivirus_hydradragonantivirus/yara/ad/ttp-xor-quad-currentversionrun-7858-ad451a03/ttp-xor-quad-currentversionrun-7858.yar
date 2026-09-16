rule TTP_XOR_QUAD_CurrentVersionRun_7858 {
  strings:
    $key_7858 = { 2b 37 [2] 0f 39 [2] 24 15 [2] 0a 37 [2] 1e 2c [2] 11 36 [2] 0f 2b [2] 0d 2a [2] 16 2c [2] 0a 2b [2] 16 04 }

  condition:
    any of them
}