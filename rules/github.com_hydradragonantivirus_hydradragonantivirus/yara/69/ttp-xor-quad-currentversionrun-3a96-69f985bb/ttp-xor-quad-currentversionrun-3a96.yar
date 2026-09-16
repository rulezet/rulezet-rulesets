rule TTP_XOR_QUAD_CurrentVersionRun_3a96 {
  strings:
    $key_3a96 = { 69 f9 [2] 4d f7 [2] 66 db [2] 48 f9 [2] 5c e2 [2] 53 f8 [2] 4d e5 [2] 4f e4 [2] 54 e2 [2] 48 e5 [2] 54 ca }

  condition:
    any of them
}