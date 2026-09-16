rule TTP_XOR_QUAD_CurrentVersionRun_5047 {
  strings:
    $key_5047 = { 03 28 [2] 27 26 [2] 0c 0a [2] 22 28 [2] 36 33 [2] 39 29 [2] 27 34 [2] 25 35 [2] 3e 33 [2] 22 34 [2] 3e 1b }

  condition:
    any of them
}