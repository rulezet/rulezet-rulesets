rule TTP_XOR_QUAD_CurrentVersionRun_6d78 {
  strings:
    $key_6d78 = { 3e 17 [2] 1a 19 [2] 31 35 [2] 1f 17 [2] 0b 0c [2] 04 16 [2] 1a 0b [2] 18 0a [2] 03 0c [2] 1f 0b [2] 03 24 }

  condition:
    any of them
}