rule TTP_XOR_QUAD_CurrentVersionRun_a087 {
  strings:
    $key_a087 = { f3 e8 [2] d7 e6 [2] fc ca [2] d2 e8 [2] c6 f3 [2] c9 e9 [2] d7 f4 [2] d5 f5 [2] ce f3 [2] d2 f4 [2] ce db }

  condition:
    any of them
}