rule TTP_XOR_QUAD_CurrentVersionRun_23e8 {
  strings:
    $key_23e8 = { 70 87 [2] 54 89 [2] 7f a5 [2] 51 87 [2] 45 9c [2] 4a 86 [2] 54 9b [2] 56 9a [2] 4d 9c [2] 51 9b [2] 4d b4 }

  condition:
    any of them
}