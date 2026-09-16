rule TTP_XOR_QUAD_CurrentVersionRun_5209 {
  strings:
    $key_5209 = { 01 66 [2] 25 68 [2] 0e 44 [2] 20 66 [2] 34 7d [2] 3b 67 [2] 25 7a [2] 27 7b [2] 3c 7d [2] 20 7a [2] 3c 55 }

  condition:
    any of them
}