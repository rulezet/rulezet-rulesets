rule TTP_XOR_QUAD_CurrentVersionRun_2514 {
  strings:
    $key_2514 = { 76 7b [2] 52 75 [2] 79 59 [2] 57 7b [2] 43 60 [2] 4c 7a [2] 52 67 [2] 50 66 [2] 4b 60 [2] 57 67 [2] 4b 48 }

  condition:
    any of them
}