rule TTP_XOR_QUAD_CurrentVersionRun_e896 {
  strings:
    $key_e896 = { bb f9 [2] 9f f7 [2] b4 db [2] 9a f9 [2] 8e e2 [2] 81 f8 [2] 9f e5 [2] 9d e4 [2] 86 e2 [2] 9a e5 [2] 86 ca }

  condition:
    any of them
}