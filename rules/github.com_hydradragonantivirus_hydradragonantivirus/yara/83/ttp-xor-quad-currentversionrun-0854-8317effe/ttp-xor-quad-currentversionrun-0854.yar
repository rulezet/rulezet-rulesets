rule TTP_XOR_QUAD_CurrentVersionRun_0854 {
  strings:
    $key_0854 = { 5b 3b [2] 7f 35 [2] 54 19 [2] 7a 3b [2] 6e 20 [2] 61 3a [2] 7f 27 [2] 7d 26 [2] 66 20 [2] 7a 27 [2] 66 08 }

  condition:
    any of them
}