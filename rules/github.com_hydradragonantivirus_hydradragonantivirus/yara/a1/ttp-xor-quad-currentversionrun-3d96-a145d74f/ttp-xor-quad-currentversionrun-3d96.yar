rule TTP_XOR_QUAD_CurrentVersionRun_3d96 {
  strings:
    $key_3d96 = { 6e f9 [2] 4a f7 [2] 61 db [2] 4f f9 [2] 5b e2 [2] 54 f8 [2] 4a e5 [2] 48 e4 [2] 53 e2 [2] 4f e5 [2] 53 ca }

  condition:
    any of them
}