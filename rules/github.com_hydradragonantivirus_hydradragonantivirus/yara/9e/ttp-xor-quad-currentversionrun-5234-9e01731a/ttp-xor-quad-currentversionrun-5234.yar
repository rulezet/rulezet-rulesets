rule TTP_XOR_QUAD_CurrentVersionRun_5234 {
  strings:
    $key_5234 = { 01 5b [2] 25 55 [2] 0e 79 [2] 20 5b [2] 34 40 [2] 3b 5a [2] 25 47 [2] 27 46 [2] 3c 40 [2] 20 47 [2] 3c 68 }

  condition:
    any of them
}