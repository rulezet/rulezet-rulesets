rule TTP_XOR_QUAD_CurrentVersionRun_1028 {
  strings:
    $key_1028 = { 43 47 [2] 67 49 [2] 4c 65 [2] 62 47 [2] 76 5c [2] 79 46 [2] 67 5b [2] 65 5a [2] 7e 5c [2] 62 5b [2] 7e 74 }

  condition:
    any of them
}