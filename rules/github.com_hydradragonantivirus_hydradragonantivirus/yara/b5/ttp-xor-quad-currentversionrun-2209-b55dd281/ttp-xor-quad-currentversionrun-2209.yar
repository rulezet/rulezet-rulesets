rule TTP_XOR_QUAD_CurrentVersionRun_2209 {
  strings:
    $key_2209 = { 71 66 [2] 55 68 [2] 7e 44 [2] 50 66 [2] 44 7d [2] 4b 67 [2] 55 7a [2] 57 7b [2] 4c 7d [2] 50 7a [2] 4c 55 }

  condition:
    any of them
}