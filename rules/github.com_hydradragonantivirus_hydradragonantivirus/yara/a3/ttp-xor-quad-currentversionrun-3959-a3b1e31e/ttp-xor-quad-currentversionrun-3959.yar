rule TTP_XOR_QUAD_CurrentVersionRun_3959 {
  strings:
    $key_3959 = { 6a 36 [2] 4e 38 [2] 65 14 [2] 4b 36 [2] 5f 2d [2] 50 37 [2] 4e 2a [2] 4c 2b [2] 57 2d [2] 4b 2a [2] 57 05 }

  condition:
    any of them
}