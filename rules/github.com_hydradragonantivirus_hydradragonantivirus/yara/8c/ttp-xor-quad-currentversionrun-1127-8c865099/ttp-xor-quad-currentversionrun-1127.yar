rule TTP_XOR_QUAD_CurrentVersionRun_1127 {
  strings:
    $key_1127 = { 42 48 [2] 66 46 [2] 4d 6a [2] 63 48 [2] 77 53 [2] 78 49 [2] 66 54 [2] 64 55 [2] 7f 53 [2] 63 54 [2] 7f 7b }

  condition:
    any of them
}