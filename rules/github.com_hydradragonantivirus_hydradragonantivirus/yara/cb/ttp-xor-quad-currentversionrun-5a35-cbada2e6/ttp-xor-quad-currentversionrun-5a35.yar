rule TTP_XOR_QUAD_CurrentVersionRun_5a35 {
  strings:
    $key_5a35 = { 09 5a [2] 2d 54 [2] 06 78 [2] 28 5a [2] 3c 41 [2] 33 5b [2] 2d 46 [2] 2f 47 [2] 34 41 [2] 28 46 [2] 34 69 }

  condition:
    any of them
}