rule TTP_XOR_QUAD_CurrentVersionRun_cd85 {
  strings:
    $key_cd85 = { 9e ea [2] ba e4 [2] 91 c8 [2] bf ea [2] ab f1 [2] a4 eb [2] ba f6 [2] b8 f7 [2] a3 f1 [2] bf f6 [2] a3 d9 }

  condition:
    any of them
}