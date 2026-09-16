rule TTP_XOR_QUAD_CurrentVersionRun_2308 {
  strings:
    $key_2308 = { 70 67 [2] 54 69 [2] 7f 45 [2] 51 67 [2] 45 7c [2] 4a 66 [2] 54 7b [2] 56 7a [2] 4d 7c [2] 51 7b [2] 4d 54 }

  condition:
    any of them
}