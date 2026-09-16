rule TTP_XOR_QUAD_CurrentVersionRun_d48c {
  strings:
    $key_d48c = { 87 e3 [2] a3 ed [2] 88 c1 [2] a6 e3 [2] b2 f8 [2] bd e2 [2] a3 ff [2] a1 fe [2] ba f8 [2] a6 ff [2] ba d0 }

  condition:
    any of them
}