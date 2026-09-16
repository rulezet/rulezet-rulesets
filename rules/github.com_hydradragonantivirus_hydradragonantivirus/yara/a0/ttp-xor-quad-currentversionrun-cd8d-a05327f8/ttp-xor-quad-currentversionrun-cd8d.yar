rule TTP_XOR_QUAD_CurrentVersionRun_cd8d {
  strings:
    $key_cd8d = { 9e e2 [2] ba ec [2] 91 c0 [2] bf e2 [2] ab f9 [2] a4 e3 [2] ba fe [2] b8 ff [2] a3 f9 [2] bf fe [2] a3 d1 }

  condition:
    any of them
}