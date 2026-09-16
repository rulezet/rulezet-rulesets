rule TTP_XOR_QUAD_CurrentVersionRun_3996 {
  strings:
    $key_3996 = { 6a f9 [2] 4e f7 [2] 65 db [2] 4b f9 [2] 5f e2 [2] 50 f8 [2] 4e e5 [2] 4c e4 [2] 57 e2 [2] 4b e5 [2] 57 ca }

  condition:
    any of them
}