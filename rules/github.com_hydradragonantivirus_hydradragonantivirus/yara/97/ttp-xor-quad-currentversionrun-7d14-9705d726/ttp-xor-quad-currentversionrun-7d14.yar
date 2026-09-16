rule TTP_XOR_QUAD_CurrentVersionRun_7d14 {
  strings:
    $key_7d14 = { 2e 7b [2] 0a 75 [2] 21 59 [2] 0f 7b [2] 1b 60 [2] 14 7a [2] 0a 67 [2] 08 66 [2] 13 60 [2] 0f 67 [2] 13 48 }

  condition:
    any of them
}