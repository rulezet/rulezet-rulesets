rule TTP_XOR_QUAD_CurrentVersionRun_2f14 {
  strings:
    $key_2f14 = { 7c 7b [2] 58 75 [2] 73 59 [2] 5d 7b [2] 49 60 [2] 46 7a [2] 58 67 [2] 5a 66 [2] 41 60 [2] 5d 67 [2] 41 48 }

  condition:
    any of them
}