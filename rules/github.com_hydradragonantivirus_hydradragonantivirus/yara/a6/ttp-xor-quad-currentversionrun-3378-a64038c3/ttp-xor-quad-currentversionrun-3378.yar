rule TTP_XOR_QUAD_CurrentVersionRun_3378 {
  strings:
    $key_3378 = { 60 17 [2] 44 19 [2] 6f 35 [2] 41 17 [2] 55 0c [2] 5a 16 [2] 44 0b [2] 46 0a [2] 5d 0c [2] 41 0b [2] 5d 24 }

  condition:
    any of them
}