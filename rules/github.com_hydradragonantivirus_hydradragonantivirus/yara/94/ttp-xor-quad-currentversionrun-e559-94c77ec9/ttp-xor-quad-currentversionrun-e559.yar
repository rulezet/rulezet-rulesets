rule TTP_XOR_QUAD_CurrentVersionRun_e559 {
  strings:
    $key_e559 = { b6 36 [2] 92 38 [2] b9 14 [2] 97 36 [2] 83 2d [2] 8c 37 [2] 92 2a [2] 90 2b [2] 8b 2d [2] 97 2a [2] 8b 05 }

  condition:
    any of them
}