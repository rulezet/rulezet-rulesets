rule TTP_XOR_QUAD_CurrentVersionRun_1b44 {
  strings:
    $key_1b44 = { 48 2b [2] 6c 25 [2] 47 09 [2] 69 2b [2] 7d 30 [2] 72 2a [2] 6c 37 [2] 6e 36 [2] 75 30 [2] 69 37 [2] 75 18 }

  condition:
    any of them
}