rule TTP_XOR_QUAD_CurrentVersionRun_4351 {
  strings:
    $key_4351 = { 10 3e [2] 34 30 [2] 1f 1c [2] 31 3e [2] 25 25 [2] 2a 3f [2] 34 22 [2] 36 23 [2] 2d 25 [2] 31 22 [2] 2d 0d }

  condition:
    any of them
}