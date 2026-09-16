rule TTP_XOR_QUAD_CurrentVersionRun_e190 {
  strings:
    $key_e190 = { b2 ff [2] 96 f1 [2] bd dd [2] 93 ff [2] 87 e4 [2] 88 fe [2] 96 e3 [2] 94 e2 [2] 8f e4 [2] 93 e3 [2] 8f cc }

  condition:
    any of them
}