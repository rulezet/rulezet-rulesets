rule TTP_XOR_QUAD_CurrentVersionRun_fa91 {
  strings:
    $key_fa91 = { a9 fe [2] 8d f0 [2] a6 dc [2] 88 fe [2] 9c e5 [2] 93 ff [2] 8d e2 [2] 8f e3 [2] 94 e5 [2] 88 e2 [2] 94 cd }

  condition:
    any of them
}