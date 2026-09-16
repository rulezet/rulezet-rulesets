rule TTP_XOR_QUAD_CurrentVersionRun_ca8a {
  strings:
    $key_ca8a = { 99 e5 [2] bd eb [2] 96 c7 [2] b8 e5 [2] ac fe [2] a3 e4 [2] bd f9 [2] bf f8 [2] a4 fe [2] b8 f9 [2] a4 d6 }

  condition:
    any of them
}