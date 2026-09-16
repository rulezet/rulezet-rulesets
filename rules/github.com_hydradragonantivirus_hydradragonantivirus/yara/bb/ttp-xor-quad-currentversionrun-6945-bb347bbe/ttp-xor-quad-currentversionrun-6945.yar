rule TTP_XOR_QUAD_CurrentVersionRun_6945 {
  strings:
    $key_6945 = { 3a 2a [2] 1e 24 [2] 35 08 [2] 1b 2a [2] 0f 31 [2] 00 2b [2] 1e 36 [2] 1c 37 [2] 07 31 [2] 1b 36 [2] 07 19 }

  condition:
    any of them
}