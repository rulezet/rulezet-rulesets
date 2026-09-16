rule TTP_XOR_QUAD_CurrentVersionRun_4401 {
  strings:
    $key_4401 = { 17 6e [2] 33 60 [2] 18 4c [2] 36 6e [2] 22 75 [2] 2d 6f [2] 33 72 [2] 31 73 [2] 2a 75 [2] 36 72 [2] 2a 5d }

  condition:
    any of them
}