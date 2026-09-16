rule TTP_XOR_QUAD_CurrentVersionRun_cd9e {
  strings:
    $key_cd9e = { 9e f1 [2] ba ff [2] 91 d3 [2] bf f1 [2] ab ea [2] a4 f0 [2] ba ed [2] b8 ec [2] a3 ea [2] bf ed [2] a3 c2 }

  condition:
    any of them
}