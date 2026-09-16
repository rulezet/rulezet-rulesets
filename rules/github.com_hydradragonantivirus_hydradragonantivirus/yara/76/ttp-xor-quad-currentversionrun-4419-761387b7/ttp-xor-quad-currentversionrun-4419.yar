rule TTP_XOR_QUAD_CurrentVersionRun_4419 {
  strings:
    $key_4419 = { 17 76 [2] 33 78 [2] 18 54 [2] 36 76 [2] 22 6d [2] 2d 77 [2] 33 6a [2] 31 6b [2] 2a 6d [2] 36 6a [2] 2a 45 }

  condition:
    any of them
}