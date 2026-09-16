rule TTP_XOR_QUAD_CurrentVersionRun_2959 {
  strings:
    $key_2959 = { 7a 36 [2] 5e 38 [2] 75 14 [2] 5b 36 [2] 4f 2d [2] 40 37 [2] 5e 2a [2] 5c 2b [2] 47 2d [2] 5b 2a [2] 47 05 }

  condition:
    any of them
}