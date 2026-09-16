rule TTP_XOR_QUAD_CurrentVersionRun_0d86 {
  strings:
    $key_0d86 = { 5e e9 [2] 7a e7 [2] 51 cb [2] 7f e9 [2] 6b f2 [2] 64 e8 [2] 7a f5 [2] 78 f4 [2] 63 f2 [2] 7f f5 [2] 63 da }

  condition:
    any of them
}