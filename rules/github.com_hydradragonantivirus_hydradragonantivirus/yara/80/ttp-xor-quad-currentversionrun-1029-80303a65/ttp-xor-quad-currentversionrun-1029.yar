rule TTP_XOR_QUAD_CurrentVersionRun_1029 {
  strings:
    $key_1029 = { 43 46 [2] 67 48 [2] 4c 64 [2] 62 46 [2] 76 5d [2] 79 47 [2] 67 5a [2] 65 5b [2] 7e 5d [2] 62 5a [2] 7e 75 }

  condition:
    any of them
}