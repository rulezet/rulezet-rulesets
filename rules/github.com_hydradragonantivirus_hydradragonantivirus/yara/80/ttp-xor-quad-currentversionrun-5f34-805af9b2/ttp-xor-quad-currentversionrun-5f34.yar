rule TTP_XOR_QUAD_CurrentVersionRun_5f34 {
  strings:
    $key_5f34 = { 0c 5b [2] 28 55 [2] 03 79 [2] 2d 5b [2] 39 40 [2] 36 5a [2] 28 47 [2] 2a 46 [2] 31 40 [2] 2d 47 [2] 31 68 }

  condition:
    any of them
}