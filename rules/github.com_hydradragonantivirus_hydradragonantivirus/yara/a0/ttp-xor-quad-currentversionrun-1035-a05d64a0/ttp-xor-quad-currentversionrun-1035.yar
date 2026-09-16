rule TTP_XOR_QUAD_CurrentVersionRun_1035 {
  strings:
    $key_1035 = { 43 5a [2] 67 54 [2] 4c 78 [2] 62 5a [2] 76 41 [2] 79 5b [2] 67 46 [2] 65 47 [2] 7e 41 [2] 62 46 [2] 7e 69 }

  condition:
    any of them
}