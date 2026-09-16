rule TTP_XOR_QUAD_CurrentVersionRun_6334 {
  strings:
    $key_6334 = { 30 5b [2] 14 55 [2] 3f 79 [2] 11 5b [2] 05 40 [2] 0a 5a [2] 14 47 [2] 16 46 [2] 0d 40 [2] 11 47 [2] 0d 68 }

  condition:
    any of them
}