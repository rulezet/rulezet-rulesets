rule TTP_XOR_QUAD_CurrentVersionRun_6314 {
  strings:
    $key_6314 = { 30 7b [2] 14 75 [2] 3f 59 [2] 11 7b [2] 05 60 [2] 0a 7a [2] 14 67 [2] 16 66 [2] 0d 60 [2] 11 67 [2] 0d 48 }

  condition:
    any of them
}