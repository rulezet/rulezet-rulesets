rule TTP_XOR_QUAD_CurrentVersionRun_2f05 {
  strings:
    $key_2f05 = { 7c 6a [2] 58 64 [2] 73 48 [2] 5d 6a [2] 49 71 [2] 46 6b [2] 58 76 [2] 5a 77 [2] 41 71 [2] 5d 76 [2] 41 59 }

  condition:
    any of them
}