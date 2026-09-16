rule TTP_XOR_QUAD_CurrentVersionRun_4c45 {
  strings:
    $key_4c45 = { 1f 2a [2] 3b 24 [2] 10 08 [2] 3e 2a [2] 2a 31 [2] 25 2b [2] 3b 36 [2] 39 37 [2] 22 31 [2] 3e 36 [2] 22 19 }

  condition:
    any of them
}