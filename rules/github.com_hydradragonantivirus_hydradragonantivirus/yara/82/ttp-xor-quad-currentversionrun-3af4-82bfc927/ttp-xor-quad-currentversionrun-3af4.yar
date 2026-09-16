rule TTP_XOR_QUAD_CurrentVersionRun_3af4 {
  strings:
    $key_3af4 = { 69 9b [2] 4d 95 [2] 66 b9 [2] 48 9b [2] 5c 80 [2] 53 9a [2] 4d 87 [2] 4f 86 [2] 54 80 [2] 48 87 [2] 54 a8 }

  condition:
    any of them
}