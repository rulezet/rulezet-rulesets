rule TTP_XOR_QUAD_CurrentVersionRun_4e34 {
  strings:
    $key_4e34 = { 1d 5b [2] 39 55 [2] 12 79 [2] 3c 5b [2] 28 40 [2] 27 5a [2] 39 47 [2] 3b 46 [2] 20 40 [2] 3c 47 [2] 20 68 }

  condition:
    any of them
}