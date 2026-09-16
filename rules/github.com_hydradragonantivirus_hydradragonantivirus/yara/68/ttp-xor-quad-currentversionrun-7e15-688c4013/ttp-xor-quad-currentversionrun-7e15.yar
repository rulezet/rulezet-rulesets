rule TTP_XOR_QUAD_CurrentVersionRun_7e15 {
  strings:
    $key_7e15 = { 2d 7a [2] 09 74 [2] 22 58 [2] 0c 7a [2] 18 61 [2] 17 7b [2] 09 66 [2] 0b 67 [2] 10 61 [2] 0c 66 [2] 10 49 }

  condition:
    any of them
}