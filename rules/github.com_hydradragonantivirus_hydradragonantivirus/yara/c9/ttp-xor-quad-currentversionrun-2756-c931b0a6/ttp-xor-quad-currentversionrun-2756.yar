rule TTP_XOR_QUAD_CurrentVersionRun_2756 {
  strings:
    $key_2756 = { 74 39 [2] 50 37 [2] 7b 1b [2] 55 39 [2] 41 22 [2] 4e 38 [2] 50 25 [2] 52 24 [2] 49 22 [2] 55 25 [2] 49 0a }

  condition:
    any of them
}