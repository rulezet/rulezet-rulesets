rule TTP_XOR_QUAD_CurrentVersionRun_2324 {
  strings:
    $key_2324 = { 70 4b [2] 54 45 [2] 7f 69 [2] 51 4b [2] 45 50 [2] 4a 4a [2] 54 57 [2] 56 56 [2] 4d 50 [2] 51 57 [2] 4d 78 }

  condition:
    any of them
}