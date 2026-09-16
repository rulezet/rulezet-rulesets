rule TTP_XOR_QUAD_CurrentVersionRun_6778 {
  strings:
    $key_6778 = { 34 17 [2] 10 19 [2] 3b 35 [2] 15 17 [2] 01 0c [2] 0e 16 [2] 10 0b [2] 12 0a [2] 09 0c [2] 15 0b [2] 09 24 }

  condition:
    any of them
}