rule TTP_XOR_QUAD_CurrentVersionRun_d19f {
  strings:
    $key_d19f = { 82 f0 [2] a6 fe [2] 8d d2 [2] a3 f0 [2] b7 eb [2] b8 f1 [2] a6 ec [2] a4 ed [2] bf eb [2] a3 ec [2] bf c3 }

  condition:
    any of them
}