rule TTP_XOR_QUAD_CurrentVersionRun_4412 {
  strings:
    $key_4412 = { 17 7d [2] 33 73 [2] 18 5f [2] 36 7d [2] 22 66 [2] 2d 7c [2] 33 61 [2] 31 60 [2] 2a 66 [2] 36 61 [2] 2a 4e }

  condition:
    any of them
}