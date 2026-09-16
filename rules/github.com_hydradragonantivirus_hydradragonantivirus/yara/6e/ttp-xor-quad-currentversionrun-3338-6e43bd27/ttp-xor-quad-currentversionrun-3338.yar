rule TTP_XOR_QUAD_CurrentVersionRun_3338 {
  strings:
    $key_3338 = { 60 57 [2] 44 59 [2] 6f 75 [2] 41 57 [2] 55 4c [2] 5a 56 [2] 44 4b [2] 46 4a [2] 5d 4c [2] 41 4b [2] 5d 64 }

  condition:
    any of them
}