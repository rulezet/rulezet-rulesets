rule TTP_XOR_QUAD_CurrentVersionRun_4301 {
  strings:
    $key_4301 = { 10 6e [2] 34 60 [2] 1f 4c [2] 31 6e [2] 25 75 [2] 2a 6f [2] 34 72 [2] 36 73 [2] 2d 75 [2] 31 72 [2] 2d 5d }

  condition:
    any of them
}