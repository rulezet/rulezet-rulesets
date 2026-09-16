rule TTP_XOR_QUAD_CurrentVersionRun_6de8 {
  strings:
    $key_6de8 = { 3e 87 [2] 1a 89 [2] 31 a5 [2] 1f 87 [2] 0b 9c [2] 04 86 [2] 1a 9b [2] 18 9a [2] 03 9c [2] 1f 9b [2] 03 b4 }

  condition:
    any of them
}