rule TTP_XOR_QUAD_CurrentVersionRun_149f {
  strings:
    $key_149f = { 47 f0 [2] 63 fe [2] 48 d2 [2] 66 f0 [2] 72 eb [2] 7d f1 [2] 63 ec [2] 61 ed [2] 7a eb [2] 66 ec [2] 7a c3 }

  condition:
    any of them
}