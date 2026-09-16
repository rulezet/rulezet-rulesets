rule TTP_XOR_QUAD_CurrentVersionRun_2779 {
  strings:
    $key_2779 = { 74 16 [2] 50 18 [2] 7b 34 [2] 55 16 [2] 41 0d [2] 4e 17 [2] 50 0a [2] 52 0b [2] 49 0d [2] 55 0a [2] 49 25 }

  condition:
    any of them
}