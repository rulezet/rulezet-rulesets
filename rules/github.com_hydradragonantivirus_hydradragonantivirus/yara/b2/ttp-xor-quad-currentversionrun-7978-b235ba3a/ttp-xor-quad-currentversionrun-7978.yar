rule TTP_XOR_QUAD_CurrentVersionRun_7978 {
  strings:
    $key_7978 = { 2a 17 [2] 0e 19 [2] 25 35 [2] 0b 17 [2] 1f 0c [2] 10 16 [2] 0e 0b [2] 0c 0a [2] 17 0c [2] 0b 0b [2] 17 24 }

  condition:
    any of them
}