rule TTP_XOR_QUAD_CurrentVersionRun_e8fa {
  strings:
    $key_e8fa = { bb 95 [2] 9f 9b [2] b4 b7 [2] 9a 95 [2] 8e 8e [2] 81 94 [2] 9f 89 [2] 9d 88 [2] 86 8e [2] 9a 89 [2] 86 a6 }

  condition:
    any of them
}