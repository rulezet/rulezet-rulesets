rule TTP_XOR_QUAD_CurrentVersionRun_26e8 {
  strings:
    $key_26e8 = { 75 87 [2] 51 89 [2] 7a a5 [2] 54 87 [2] 40 9c [2] 4f 86 [2] 51 9b [2] 53 9a [2] 48 9c [2] 54 9b [2] 48 b4 }

  condition:
    any of them
}