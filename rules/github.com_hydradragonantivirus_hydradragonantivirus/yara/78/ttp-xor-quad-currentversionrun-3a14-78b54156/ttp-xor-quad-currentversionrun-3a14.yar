rule TTP_XOR_QUAD_CurrentVersionRun_3a14 {
  strings:
    $key_3a14 = { 69 7b [2] 4d 75 [2] 66 59 [2] 48 7b [2] 5c 60 [2] 53 7a [2] 4d 67 [2] 4f 66 [2] 54 60 [2] 48 67 [2] 54 48 }

  condition:
    any of them
}