rule TTP_XOR_QUAD_CurrentVersionRun_0d96 {
  strings:
    $key_0d96 = { 5e f9 [2] 7a f7 [2] 51 db [2] 7f f9 [2] 6b e2 [2] 64 f8 [2] 7a e5 [2] 78 e4 [2] 63 e2 [2] 7f e5 [2] 63 ca }

  condition:
    any of them
}