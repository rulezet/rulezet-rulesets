rule TTP_XOR_QUAD_CurrentVersionRun_2205 {
  strings:
    $key_2205 = { 71 6a [2] 55 64 [2] 7e 48 [2] 50 6a [2] 44 71 [2] 4b 6b [2] 55 76 [2] 57 77 [2] 4c 71 [2] 50 76 [2] 4c 59 }

  condition:
    any of them
}