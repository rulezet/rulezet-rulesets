rule TTP_XOR_QUAD_CurrentVersionRun_5856 {
  strings:
    $key_5856 = { 0b 39 [2] 2f 37 [2] 04 1b [2] 2a 39 [2] 3e 22 [2] 31 38 [2] 2f 25 [2] 2d 24 [2] 36 22 [2] 2a 25 [2] 36 0a }

  condition:
    any of them
}