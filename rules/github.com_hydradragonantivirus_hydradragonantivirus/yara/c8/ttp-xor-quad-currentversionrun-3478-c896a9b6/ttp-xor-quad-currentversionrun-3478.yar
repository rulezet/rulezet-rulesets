rule TTP_XOR_QUAD_CurrentVersionRun_3478 {
  strings:
    $key_3478 = { 67 17 [2] 43 19 [2] 68 35 [2] 46 17 [2] 52 0c [2] 5d 16 [2] 43 0b [2] 41 0a [2] 5a 0c [2] 46 0b [2] 5a 24 }

  condition:
    any of them
}