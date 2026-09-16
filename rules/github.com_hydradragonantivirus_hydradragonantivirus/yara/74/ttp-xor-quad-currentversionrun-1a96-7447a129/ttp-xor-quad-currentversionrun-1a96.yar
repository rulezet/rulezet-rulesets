rule TTP_XOR_QUAD_CurrentVersionRun_1a96 {
  strings:
    $key_1a96 = { 49 f9 [2] 6d f7 [2] 46 db [2] 68 f9 [2] 7c e2 [2] 73 f8 [2] 6d e5 [2] 6f e4 [2] 74 e2 [2] 68 e5 [2] 74 ca }

  condition:
    any of them
}