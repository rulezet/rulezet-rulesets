rule TTP_XOR_QUAD_CurrentVersionRun_3f96 {
  strings:
    $key_3f96 = { 6c f9 [2] 48 f7 [2] 63 db [2] 4d f9 [2] 59 e2 [2] 56 f8 [2] 48 e5 [2] 4a e4 [2] 51 e2 [2] 4d e5 [2] 51 ca }

  condition:
    any of them
}