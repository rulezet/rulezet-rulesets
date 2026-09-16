rule TTP_XOR_QUAD_CurrentVersionRun_3e14 {
  strings:
    $key_3e14 = { 6d 7b [2] 49 75 [2] 62 59 [2] 4c 7b [2] 58 60 [2] 57 7a [2] 49 67 [2] 4b 66 [2] 50 60 [2] 4c 67 [2] 50 48 }

  condition:
    any of them
}