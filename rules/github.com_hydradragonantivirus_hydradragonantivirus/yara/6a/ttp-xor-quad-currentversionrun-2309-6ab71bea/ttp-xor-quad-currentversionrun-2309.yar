rule TTP_XOR_QUAD_CurrentVersionRun_2309 {
  strings:
    $key_2309 = { 70 66 [2] 54 68 [2] 7f 44 [2] 51 66 [2] 45 7d [2] 4a 67 [2] 54 7a [2] 56 7b [2] 4d 7d [2] 51 7a [2] 4d 55 }

  condition:
    any of them
}