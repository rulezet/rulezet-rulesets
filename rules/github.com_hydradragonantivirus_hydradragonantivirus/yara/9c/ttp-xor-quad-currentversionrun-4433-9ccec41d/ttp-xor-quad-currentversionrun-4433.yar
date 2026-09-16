rule TTP_XOR_QUAD_CurrentVersionRun_4433 {
  strings:
    $key_4433 = { 17 5c [2] 33 52 [2] 18 7e [2] 36 5c [2] 22 47 [2] 2d 5d [2] 33 40 [2] 31 41 [2] 2a 47 [2] 36 40 [2] 2a 6f }

  condition:
    any of them
}