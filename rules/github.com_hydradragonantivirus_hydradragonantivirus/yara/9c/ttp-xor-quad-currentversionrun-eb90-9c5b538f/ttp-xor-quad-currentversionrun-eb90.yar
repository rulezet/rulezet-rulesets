rule TTP_XOR_QUAD_CurrentVersionRun_eb90 {
  strings:
    $key_eb90 = { b8 ff [2] 9c f1 [2] b7 dd [2] 99 ff [2] 8d e4 [2] 82 fe [2] 9c e3 [2] 9e e2 [2] 85 e4 [2] 99 e3 [2] 85 cc }

  condition:
    any of them
}