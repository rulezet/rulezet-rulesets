rule TTP_XOR_QUAD_CurrentVersionRun_6a78 {
  strings:
    $key_6a78 = { 39 17 [2] 1d 19 [2] 36 35 [2] 18 17 [2] 0c 0c [2] 03 16 [2] 1d 0b [2] 1f 0a [2] 04 0c [2] 18 0b [2] 04 24 }

  condition:
    any of them
}