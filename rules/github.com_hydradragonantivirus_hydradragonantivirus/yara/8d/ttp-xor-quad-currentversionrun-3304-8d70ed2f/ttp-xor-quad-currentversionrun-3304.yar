rule TTP_XOR_QUAD_CurrentVersionRun_3304 {
  strings:
    $key_3304 = { 60 6b [2] 44 65 [2] 6f 49 [2] 41 6b [2] 55 70 [2] 5a 6a [2] 44 77 [2] 46 76 [2] 5d 70 [2] 41 77 [2] 5d 58 }

  condition:
    any of them
}