rule TTP_XOR_QUAD_CurrentVersionRun_4c44 {
  strings:
    $key_4c44 = { 1f 2b [2] 3b 25 [2] 10 09 [2] 3e 2b [2] 2a 30 [2] 25 2a [2] 3b 37 [2] 39 36 [2] 22 30 [2] 3e 37 [2] 22 18 }

  condition:
    any of them
}