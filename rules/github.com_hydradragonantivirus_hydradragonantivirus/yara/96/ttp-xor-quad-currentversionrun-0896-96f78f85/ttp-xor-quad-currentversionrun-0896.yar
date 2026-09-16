rule TTP_XOR_QUAD_CurrentVersionRun_0896 {
  strings:
    $key_0896 = { 5b f9 [2] 7f f7 [2] 54 db [2] 7a f9 [2] 6e e2 [2] 61 f8 [2] 7f e5 [2] 7d e4 [2] 66 e2 [2] 7a e5 [2] 66 ca }

  condition:
    any of them
}