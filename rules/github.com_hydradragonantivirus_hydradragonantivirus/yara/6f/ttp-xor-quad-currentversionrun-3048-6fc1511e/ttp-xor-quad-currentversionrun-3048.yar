rule TTP_XOR_QUAD_CurrentVersionRun_3048 {
  strings:
    $key_3048 = { 63 27 [2] 47 29 [2] 6c 05 [2] 42 27 [2] 56 3c [2] 59 26 [2] 47 3b [2] 45 3a [2] 5e 3c [2] 42 3b [2] 5e 14 }

  condition:
    any of them
}