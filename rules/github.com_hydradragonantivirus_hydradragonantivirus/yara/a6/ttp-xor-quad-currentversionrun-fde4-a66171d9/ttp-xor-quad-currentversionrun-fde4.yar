rule TTP_XOR_QUAD_CurrentVersionRun_fde4 {
  strings:
    $key_fde4 = { ae 8b [2] 8a 85 [2] a1 a9 [2] 8f 8b [2] 9b 90 [2] 94 8a [2] 8a 97 [2] 88 96 [2] 93 90 [2] 8f 97 [2] 93 b8 }

  condition:
    any of them
}