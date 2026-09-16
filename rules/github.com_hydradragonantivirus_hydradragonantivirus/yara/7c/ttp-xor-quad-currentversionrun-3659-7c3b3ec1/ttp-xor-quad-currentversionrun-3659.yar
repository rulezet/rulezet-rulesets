rule TTP_XOR_QUAD_CurrentVersionRun_3659 {
  strings:
    $key_3659 = { 65 36 [2] 41 38 [2] 6a 14 [2] 44 36 [2] 50 2d [2] 5f 37 [2] 41 2a [2] 43 2b [2] 58 2d [2] 44 2a [2] 58 05 }

  condition:
    any of them
}