rule TTP_XOR_QUAD_CurrentVersionRun_c89e {
  strings:
    $key_c89e = { 9b f1 [2] bf ff [2] 94 d3 [2] ba f1 [2] ae ea [2] a1 f0 [2] bf ed [2] bd ec [2] a6 ea [2] ba ed [2] a6 c2 }

  condition:
    any of them
}