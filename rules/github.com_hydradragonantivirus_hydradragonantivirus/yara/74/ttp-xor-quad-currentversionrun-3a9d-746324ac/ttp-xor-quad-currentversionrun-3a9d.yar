rule TTP_XOR_QUAD_CurrentVersionRun_3a9d {
  strings:
    $key_3a9d = { 69 f2 [2] 4d fc [2] 66 d0 [2] 48 f2 [2] 5c e9 [2] 53 f3 [2] 4d ee [2] 4f ef [2] 54 e9 [2] 48 ee [2] 54 c1 }

  condition:
    any of them
}