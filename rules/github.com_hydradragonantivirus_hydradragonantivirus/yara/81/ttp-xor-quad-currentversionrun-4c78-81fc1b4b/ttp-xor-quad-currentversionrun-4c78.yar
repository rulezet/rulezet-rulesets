rule TTP_XOR_QUAD_CurrentVersionRun_4c78 {
  strings:
    $key_4c78 = { 1f 17 [2] 3b 19 [2] 10 35 [2] 3e 17 [2] 2a 0c [2] 25 16 [2] 3b 0b [2] 39 0a [2] 22 0c [2] 3e 0b [2] 22 24 }

  condition:
    any of them
}