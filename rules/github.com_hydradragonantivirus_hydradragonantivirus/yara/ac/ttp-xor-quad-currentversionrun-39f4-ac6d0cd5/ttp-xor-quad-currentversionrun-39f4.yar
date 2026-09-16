rule TTP_XOR_QUAD_CurrentVersionRun_39f4 {
  strings:
    $key_39f4 = { 6a 9b [2] 4e 95 [2] 65 b9 [2] 4b 9b [2] 5f 80 [2] 50 9a [2] 4e 87 [2] 4c 86 [2] 57 80 [2] 4b 87 [2] 57 a8 }

  condition:
    any of them
}