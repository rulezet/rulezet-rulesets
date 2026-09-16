rule TTP_XOR_QUAD_CurrentVersionRun_e996 {
  strings:
    $key_e996 = { ba f9 [2] 9e f7 [2] b5 db [2] 9b f9 [2] 8f e2 [2] 80 f8 [2] 9e e5 [2] 9c e4 [2] 87 e2 [2] 9b e5 [2] 87 ca }

  condition:
    any of them
}