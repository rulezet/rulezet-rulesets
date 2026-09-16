rule TTP_XOR_QUAD_CurrentVersionRun_3244 {
  strings:
    $key_3244 = { 61 2b [2] 45 25 [2] 6e 09 [2] 40 2b [2] 54 30 [2] 5b 2a [2] 45 37 [2] 47 36 [2] 5c 30 [2] 40 37 [2] 5c 18 }

  condition:
    any of them
}