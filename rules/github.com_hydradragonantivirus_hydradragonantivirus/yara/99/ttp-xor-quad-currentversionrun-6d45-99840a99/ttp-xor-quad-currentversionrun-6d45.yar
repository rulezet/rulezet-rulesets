rule TTP_XOR_QUAD_CurrentVersionRun_6d45 {
  strings:
    $key_6d45 = { 3e 2a [2] 1a 24 [2] 31 08 [2] 1f 2a [2] 0b 31 [2] 04 2b [2] 1a 36 [2] 18 37 [2] 03 31 [2] 1f 36 [2] 03 19 }

  condition:
    any of them
}