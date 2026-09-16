rule TTP_XOR_QUAD_CurrentVersionRun_7e78 {
  strings:
    $key_7e78 = { 2d 17 [2] 09 19 [2] 22 35 [2] 0c 17 [2] 18 0c [2] 17 16 [2] 09 0b [2] 0b 0a [2] 10 0c [2] 0c 0b [2] 10 24 }

  condition:
    any of them
}