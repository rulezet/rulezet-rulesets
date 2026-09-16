rule TTP_XOR_QUAD_CurrentVersionRun_5278 {
  strings:
    $key_5278 = { 01 17 [2] 25 19 [2] 0e 35 [2] 20 17 [2] 34 0c [2] 3b 16 [2] 25 0b [2] 27 0a [2] 3c 0c [2] 20 0b [2] 3c 24 }

  condition:
    any of them
}