rule TTP_XOR_QUAD_CurrentVersionRun_43f4 {
  strings:
    $key_43f4 = { 10 9b [2] 34 95 [2] 1f b9 [2] 31 9b [2] 25 80 [2] 2a 9a [2] 34 87 [2] 36 86 [2] 2d 80 [2] 31 87 [2] 2d a8 }

  condition:
    any of them
}