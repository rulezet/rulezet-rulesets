rule TTP_XOR_QUAD_CurrentVersionRun_0c48 {
  strings:
    $key_0c48 = { 5f 27 [2] 7b 29 [2] 50 05 [2] 7e 27 [2] 6a 3c [2] 65 26 [2] 7b 3b [2] 79 3a [2] 62 3c [2] 7e 3b [2] 62 14 }

  condition:
    any of them
}