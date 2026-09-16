rule TTP_XOR_QUAD_CurrentVersionRun_5238 {
  strings:
    $key_5238 = { 01 57 [2] 25 59 [2] 0e 75 [2] 20 57 [2] 34 4c [2] 3b 56 [2] 25 4b [2] 27 4a [2] 3c 4c [2] 20 4b [2] 3c 64 }

  condition:
    any of them
}