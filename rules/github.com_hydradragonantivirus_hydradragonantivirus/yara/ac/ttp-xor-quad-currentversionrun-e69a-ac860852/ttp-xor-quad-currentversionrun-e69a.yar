rule TTP_XOR_QUAD_CurrentVersionRun_e69a {
  strings:
    $key_e69a = { b5 f5 [2] 91 fb [2] ba d7 [2] 94 f5 [2] 80 ee [2] 8f f4 [2] 91 e9 [2] 93 e8 [2] 88 ee [2] 94 e9 [2] 88 c6 }

  condition:
    any of them
}