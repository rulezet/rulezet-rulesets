rule TTP_XOR_QUAD_CurrentVersionRun_e686 {
  strings:
    $key_e686 = { b5 e9 [2] 91 e7 [2] ba cb [2] 94 e9 [2] 80 f2 [2] 8f e8 [2] 91 f5 [2] 93 f4 [2] 88 f2 [2] 94 f5 [2] 88 da }

  condition:
    any of them
}