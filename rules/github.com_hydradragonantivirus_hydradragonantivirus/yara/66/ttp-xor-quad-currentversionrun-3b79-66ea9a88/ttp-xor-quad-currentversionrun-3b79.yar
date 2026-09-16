rule TTP_XOR_QUAD_CurrentVersionRun_3b79 {
  strings:
    $key_3b79 = { 68 16 [2] 4c 18 [2] 67 34 [2] 49 16 [2] 5d 0d [2] 52 17 [2] 4c 0a [2] 4e 0b [2] 55 0d [2] 49 0a [2] 55 25 }

  condition:
    any of them
}