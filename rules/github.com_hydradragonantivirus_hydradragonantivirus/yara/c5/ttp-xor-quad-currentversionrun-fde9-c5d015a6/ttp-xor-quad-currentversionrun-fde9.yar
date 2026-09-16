rule TTP_XOR_QUAD_CurrentVersionRun_fde9 {
  strings:
    $key_fde9 = { ae 86 [2] 8a 88 [2] a1 a4 [2] 8f 86 [2] 9b 9d [2] 94 87 [2] 8a 9a [2] 88 9b [2] 93 9d [2] 8f 9a [2] 93 b5 }

  condition:
    any of them
}