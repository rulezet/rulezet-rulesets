rule TTP_XOR_QUAD_CurrentVersionRun_4451 {
  strings:
    $key_4451 = { 17 3e [2] 33 30 [2] 18 1c [2] 36 3e [2] 22 25 [2] 2d 3f [2] 33 22 [2] 31 23 [2] 2a 25 [2] 36 22 [2] 2a 0d }

  condition:
    any of them
}