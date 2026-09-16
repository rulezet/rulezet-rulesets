rule TTP_XOR_QUAD_CurrentVersionRun_fde5 {
  strings:
    $key_fde5 = { ae 8a [2] 8a 84 [2] a1 a8 [2] 8f 8a [2] 9b 91 [2] 94 8b [2] 8a 96 [2] 88 97 [2] 93 91 [2] 8f 96 [2] 93 b9 }

  condition:
    any of them
}