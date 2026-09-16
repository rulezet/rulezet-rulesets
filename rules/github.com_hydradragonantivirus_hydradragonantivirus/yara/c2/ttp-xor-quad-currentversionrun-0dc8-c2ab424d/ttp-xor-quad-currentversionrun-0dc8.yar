rule TTP_XOR_QUAD_CurrentVersionRun_0dc8 {
  strings:
    $key_0dc8 = { 5e a7 [2] 7a a9 [2] 51 85 [2] 7f a7 [2] 6b bc [2] 64 a6 [2] 7a bb [2] 78 ba [2] 63 bc [2] 7f bb [2] 63 94 }

  condition:
    any of them
}