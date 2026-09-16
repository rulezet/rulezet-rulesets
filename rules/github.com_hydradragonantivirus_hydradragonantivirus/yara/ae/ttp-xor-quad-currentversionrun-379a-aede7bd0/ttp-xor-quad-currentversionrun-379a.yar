rule TTP_XOR_QUAD_CurrentVersionRun_379a {
  strings:
    $key_379a = { 64 f5 [2] 40 fb [2] 6b d7 [2] 45 f5 [2] 51 ee [2] 5e f4 [2] 40 e9 [2] 42 e8 [2] 59 ee [2] 45 e9 [2] 59 c6 }

  condition:
    any of them
}