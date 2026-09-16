rule TTP_XOR_QUAD_CurrentVersionRun_0a96 {
  strings:
    $key_0a96 = { 59 f9 [2] 7d f7 [2] 56 db [2] 78 f9 [2] 6c e2 [2] 63 f8 [2] 7d e5 [2] 7f e4 [2] 64 e2 [2] 78 e5 [2] 64 ca }

  condition:
    any of them
}