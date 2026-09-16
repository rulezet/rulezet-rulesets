rule TTP_XOR_QUAD_CurrentVersionRun_3609 {
  strings:
    $key_3609 = { 65 66 [2] 41 68 [2] 6a 44 [2] 44 66 [2] 50 7d [2] 5f 67 [2] 41 7a [2] 43 7b [2] 58 7d [2] 44 7a [2] 58 55 }

  condition:
    any of them
}