rule TTP_XOR_QUAD_CurrentVersionRun_1734 {
  strings:
    $key_1734 = { 44 5b [2] 60 55 [2] 4b 79 [2] 65 5b [2] 71 40 [2] 7e 5a [2] 60 47 [2] 62 46 [2] 79 40 [2] 65 47 [2] 79 68 }

  condition:
    any of them
}