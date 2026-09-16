rule TTP_XOR_QUAD_CurrentVersionRun_3305 {
  strings:
    $key_3305 = { 60 6a [2] 44 64 [2] 6f 48 [2] 41 6a [2] 55 71 [2] 5a 6b [2] 44 76 [2] 46 77 [2] 5d 71 [2] 41 76 [2] 5d 59 }

  condition:
    any of them
}