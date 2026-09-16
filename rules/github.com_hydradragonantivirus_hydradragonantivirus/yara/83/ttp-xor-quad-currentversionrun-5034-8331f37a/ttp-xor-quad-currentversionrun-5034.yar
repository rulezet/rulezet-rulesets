rule TTP_XOR_QUAD_CurrentVersionRun_5034 {
  strings:
    $key_5034 = { 03 5b [2] 27 55 [2] 0c 79 [2] 22 5b [2] 36 40 [2] 39 5a [2] 27 47 [2] 25 46 [2] 3e 40 [2] 22 47 [2] 3e 68 }

  condition:
    any of them
}