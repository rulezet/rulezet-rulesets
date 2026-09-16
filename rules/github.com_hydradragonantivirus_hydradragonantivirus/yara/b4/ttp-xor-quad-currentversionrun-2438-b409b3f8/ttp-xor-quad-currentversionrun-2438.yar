rule TTP_XOR_QUAD_CurrentVersionRun_2438 {
  strings:
    $key_2438 = { 77 57 [2] 53 59 [2] 78 75 [2] 56 57 [2] 42 4c [2] 4d 56 [2] 53 4b [2] 51 4a [2] 4a 4c [2] 56 4b [2] 4a 64 }

  condition:
    any of them
}