rule TTP_XOR_QUAD_CurrentVersionRun_4312 {
  strings:
    $key_4312 = { 10 7d [2] 34 73 [2] 1f 5f [2] 31 7d [2] 25 66 [2] 2a 7c [2] 34 61 [2] 36 60 [2] 2d 66 [2] 31 61 [2] 2d 4e }

  condition:
    any of them
}