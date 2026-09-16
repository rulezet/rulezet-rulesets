rule TTP_XOR_QUAD_CurrentVersionRun_0778 {
  strings:
    $key_0778 = { 54 17 [2] 70 19 [2] 5b 35 [2] 75 17 [2] 61 0c [2] 6e 16 [2] 70 0b [2] 72 0a [2] 69 0c [2] 75 0b [2] 69 24 }

  condition:
    any of them
}