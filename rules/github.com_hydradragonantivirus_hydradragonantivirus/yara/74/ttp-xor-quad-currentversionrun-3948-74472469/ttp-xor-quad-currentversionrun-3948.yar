rule TTP_XOR_QUAD_CurrentVersionRun_3948 {
  strings:
    $key_3948 = { 6a 27 [2] 4e 29 [2] 65 05 [2] 4b 27 [2] 5f 3c [2] 50 26 [2] 4e 3b [2] 4c 3a [2] 57 3c [2] 4b 3b [2] 57 14 }

  condition:
    any of them
}