rule TTP_XOR_QUAD_CurrentVersionRun_3f48 {
  strings:
    $key_3f48 = { 6c 27 [2] 48 29 [2] 63 05 [2] 4d 27 [2] 59 3c [2] 56 26 [2] 48 3b [2] 4a 3a [2] 51 3c [2] 4d 3b [2] 51 14 }

  condition:
    any of them
}