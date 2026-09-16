rule TTP_XOR_QUAD_CurrentVersionRun_50f4 {
  strings:
    $key_50f4 = { 03 9b [2] 27 95 [2] 0c b9 [2] 22 9b [2] 36 80 [2] 39 9a [2] 27 87 [2] 25 86 [2] 3e 80 [2] 22 87 [2] 3e a8 }

  condition:
    any of them
}