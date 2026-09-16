rule TTP_XOR_QUAD_CurrentVersionRun_5f01 {
  strings:
    $key_5f01 = { 0c 6e [2] 28 60 [2] 03 4c [2] 2d 6e [2] 39 75 [2] 36 6f [2] 28 72 [2] 2a 73 [2] 31 75 [2] 2d 72 [2] 31 5d }

  condition:
    any of them
}