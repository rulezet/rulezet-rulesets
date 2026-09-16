rule TTP_XOR_QUAD_CurrentVersionRun_4333 {
  strings:
    $key_4333 = { 10 5c [2] 34 52 [2] 1f 7e [2] 31 5c [2] 25 47 [2] 2a 5d [2] 34 40 [2] 36 41 [2] 2d 47 [2] 31 40 [2] 2d 6f }

  condition:
    any of them
}