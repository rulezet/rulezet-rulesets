rule TTP_XOR_QUAD_CurrentVersionRun_715a {
  strings:
    $key_715a = { 22 35 [2] 06 3b [2] 2d 17 [2] 03 35 [2] 17 2e [2] 18 34 [2] 06 29 [2] 04 28 [2] 1f 2e [2] 03 29 [2] 1f 06 }

  condition:
    any of them
}