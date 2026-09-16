rule TTP_XOR_QUAD_CurrentVersionRun_4996 {
  strings:
    $key_4996 = { 1a f9 [2] 3e f7 [2] 15 db [2] 3b f9 [2] 2f e2 [2] 20 f8 [2] 3e e5 [2] 3c e4 [2] 27 e2 [2] 3b e5 [2] 27 ca }

  condition:
    any of them
}