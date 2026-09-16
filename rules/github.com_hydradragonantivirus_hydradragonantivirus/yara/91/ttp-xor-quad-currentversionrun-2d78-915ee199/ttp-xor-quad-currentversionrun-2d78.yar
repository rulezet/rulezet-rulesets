rule TTP_XOR_QUAD_CurrentVersionRun_2d78 {
  strings:
    $key_2d78 = { 7e 17 [2] 5a 19 [2] 71 35 [2] 5f 17 [2] 4b 0c [2] 44 16 [2] 5a 0b [2] 58 0a [2] 43 0c [2] 5f 0b [2] 43 24 }

  condition:
    any of them
}