rule TTP_XOR_QUAD_CurrentVersionRun_10f8 {
  strings:
    $key_10f8 = { 43 97 [2] 67 99 [2] 4c b5 [2] 62 97 [2] 76 8c [2] 79 96 [2] 67 8b [2] 65 8a [2] 7e 8c [2] 62 8b [2] 7e a4 }

  condition:
    any of them
}