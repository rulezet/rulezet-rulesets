rule TTP_XOR_QUAD_CurrentVersionRun_22e4 {
  strings:
    $key_22e4 = { 71 8b [2] 55 85 [2] 7e a9 [2] 50 8b [2] 44 90 [2] 4b 8a [2] 55 97 [2] 57 96 [2] 4c 90 [2] 50 97 [2] 4c b8 }

  condition:
    any of them
}