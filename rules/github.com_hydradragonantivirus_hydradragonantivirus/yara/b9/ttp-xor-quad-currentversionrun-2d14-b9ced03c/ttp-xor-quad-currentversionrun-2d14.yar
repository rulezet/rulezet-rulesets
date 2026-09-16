rule TTP_XOR_QUAD_CurrentVersionRun_2d14 {
  strings:
    $key_2d14 = { 7e 7b [2] 5a 75 [2] 71 59 [2] 5f 7b [2] 4b 60 [2] 44 7a [2] 5a 67 [2] 58 66 [2] 43 60 [2] 5f 67 [2] 43 48 }

  condition:
    any of them
}