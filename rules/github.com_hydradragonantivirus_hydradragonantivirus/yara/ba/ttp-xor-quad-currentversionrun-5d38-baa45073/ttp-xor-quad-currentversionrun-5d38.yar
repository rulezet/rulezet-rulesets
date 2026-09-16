rule TTP_XOR_QUAD_CurrentVersionRun_5d38 {
  strings:
    $key_5d38 = { 0e 57 [2] 2a 59 [2] 01 75 [2] 2f 57 [2] 3b 4c [2] 34 56 [2] 2a 4b [2] 28 4a [2] 33 4c [2] 2f 4b [2] 33 64 }

  condition:
    any of them
}