rule TTP_XOR_QUAD_CurrentVersionRun_e596 {
  strings:
    $key_e596 = { b6 f9 [2] 92 f7 [2] b9 db [2] 97 f9 [2] 83 e2 [2] 8c f8 [2] 92 e5 [2] 90 e4 [2] 8b e2 [2] 97 e5 [2] 8b ca }

  condition:
    any of them
}