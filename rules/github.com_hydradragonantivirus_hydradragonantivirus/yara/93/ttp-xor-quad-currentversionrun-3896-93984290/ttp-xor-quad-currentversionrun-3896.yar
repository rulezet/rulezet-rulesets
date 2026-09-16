rule TTP_XOR_QUAD_CurrentVersionRun_3896 {
  strings:
    $key_3896 = { 6b f9 [2] 4f f7 [2] 64 db [2] 4a f9 [2] 5e e2 [2] 51 f8 [2] 4f e5 [2] 4d e4 [2] 56 e2 [2] 4a e5 [2] 56 ca }

  condition:
    any of them
}