rule TTP_XOR_QUAD_CurrentVersionRun_3438 {
  strings:
    $key_3438 = { 67 57 [2] 43 59 [2] 68 75 [2] 46 57 [2] 52 4c [2] 5d 56 [2] 43 4b [2] 41 4a [2] 5a 4c [2] 46 4b [2] 5a 64 }

  condition:
    any of them
}