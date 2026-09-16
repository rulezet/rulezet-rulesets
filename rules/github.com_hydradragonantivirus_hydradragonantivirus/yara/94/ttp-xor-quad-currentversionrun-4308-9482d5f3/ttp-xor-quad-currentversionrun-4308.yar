rule TTP_XOR_QUAD_CurrentVersionRun_4308 {
  strings:
    $key_4308 = { 10 67 [2] 34 69 [2] 1f 45 [2] 31 67 [2] 25 7c [2] 2a 66 [2] 34 7b [2] 36 7a [2] 2d 7c [2] 31 7b [2] 2d 54 }

  condition:
    any of them
}