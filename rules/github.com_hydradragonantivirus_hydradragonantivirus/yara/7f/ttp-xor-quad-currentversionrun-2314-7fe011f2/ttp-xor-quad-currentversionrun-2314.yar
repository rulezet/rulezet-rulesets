rule TTP_XOR_QUAD_CurrentVersionRun_2314 {
  strings:
    $key_2314 = { 70 7b [2] 54 75 [2] 7f 59 [2] 51 7b [2] 45 60 [2] 4a 7a [2] 54 67 [2] 56 66 [2] 4d 60 [2] 51 67 [2] 4d 48 }

  condition:
    any of them
}