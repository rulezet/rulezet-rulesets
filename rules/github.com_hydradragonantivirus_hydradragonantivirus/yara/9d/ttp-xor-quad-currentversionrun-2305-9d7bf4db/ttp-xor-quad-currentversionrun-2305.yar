rule TTP_XOR_QUAD_CurrentVersionRun_2305 {
  strings:
    $key_2305 = { 70 6a [2] 54 64 [2] 7f 48 [2] 51 6a [2] 45 71 [2] 4a 6b [2] 54 76 [2] 56 77 [2] 4d 71 [2] 51 76 [2] 4d 59 }

  condition:
    any of them
}