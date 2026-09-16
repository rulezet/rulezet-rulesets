rule TTP_XOR_QUAD_CurrentVersionRun_2d54 {
  strings:
    $key_2d54 = { 7e 3b [2] 5a 35 [2] 71 19 [2] 5f 3b [2] 4b 20 [2] 44 3a [2] 5a 27 [2] 58 26 [2] 43 20 [2] 5f 27 [2] 43 08 }

  condition:
    any of them
}