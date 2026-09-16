rule TTP_XOR_QUAD_CurrentVersionRun_50f8 {
  strings:
    $key_50f8 = { 03 97 [2] 27 99 [2] 0c b5 [2] 22 97 [2] 36 8c [2] 39 96 [2] 27 8b [2] 25 8a [2] 3e 8c [2] 22 8b [2] 3e a4 }

  condition:
    any of them
}