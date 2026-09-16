rule TTP_XOR_QUAD_CurrentVersionRun_4331 {
  strings:
    $key_4331 = { 10 5e [2] 34 50 [2] 1f 7c [2] 31 5e [2] 25 45 [2] 2a 5f [2] 34 42 [2] 36 43 [2] 2d 45 [2] 31 42 [2] 2d 6d }

  condition:
    any of them
}