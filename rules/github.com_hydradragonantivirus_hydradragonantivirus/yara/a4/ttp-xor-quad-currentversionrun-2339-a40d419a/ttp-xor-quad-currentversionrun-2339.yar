rule TTP_XOR_QUAD_CurrentVersionRun_2339 {
  strings:
    $key_2339 = { 70 56 [2] 54 58 [2] 7f 74 [2] 51 56 [2] 45 4d [2] 4a 57 [2] 54 4a [2] 56 4b [2] 4d 4d [2] 51 4a [2] 4d 65 }

  condition:
    any of them
}