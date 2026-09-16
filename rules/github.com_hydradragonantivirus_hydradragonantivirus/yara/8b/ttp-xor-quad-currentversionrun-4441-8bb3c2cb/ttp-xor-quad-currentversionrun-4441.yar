rule TTP_XOR_QUAD_CurrentVersionRun_4441 {
  strings:
    $key_4441 = { 17 2e [2] 33 20 [2] 18 0c [2] 36 2e [2] 22 35 [2] 2d 2f [2] 33 32 [2] 31 33 [2] 2a 35 [2] 36 32 [2] 2a 1d }

  condition:
    any of them
}