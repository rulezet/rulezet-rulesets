rule TTP_XOR_QUAD_CurrentVersionRun_e8e9 {
  strings:
    $key_e8e9 = { bb 86 [2] 9f 88 [2] b4 a4 [2] 9a 86 [2] 8e 9d [2] 81 87 [2] 9f 9a [2] 9d 9b [2] 86 9d [2] 9a 9a [2] 86 b5 }

  condition:
    any of them
}