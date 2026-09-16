rule TTP_XOR_QUAD_CurrentVersionRun_4311 {
  strings:
    $key_4311 = { 10 7e [2] 34 70 [2] 1f 5c [2] 31 7e [2] 25 65 [2] 2a 7f [2] 34 62 [2] 36 63 [2] 2d 65 [2] 31 62 [2] 2d 4d }

  condition:
    any of them
}