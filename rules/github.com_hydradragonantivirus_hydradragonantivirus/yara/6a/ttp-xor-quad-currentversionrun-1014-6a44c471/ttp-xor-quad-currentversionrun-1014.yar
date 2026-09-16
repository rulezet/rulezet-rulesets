rule TTP_XOR_QUAD_CurrentVersionRun_1014 {
  strings:
    $key_1014 = { 43 7b [2] 67 75 [2] 4c 59 [2] 62 7b [2] 76 60 [2] 79 7a [2] 67 67 [2] 65 66 [2] 7e 60 [2] 62 67 [2] 7e 48 }

  condition:
    any of them
}