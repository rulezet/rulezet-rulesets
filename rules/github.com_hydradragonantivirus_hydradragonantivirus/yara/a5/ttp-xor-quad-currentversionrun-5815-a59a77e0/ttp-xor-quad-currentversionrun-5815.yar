rule TTP_XOR_QUAD_CurrentVersionRun_5815 {
  strings:
    $key_5815 = { 0b 7a [2] 2f 74 [2] 04 58 [2] 2a 7a [2] 3e 61 [2] 31 7b [2] 2f 66 [2] 2d 67 [2] 36 61 [2] 2a 66 [2] 36 49 }

  condition:
    any of them
}