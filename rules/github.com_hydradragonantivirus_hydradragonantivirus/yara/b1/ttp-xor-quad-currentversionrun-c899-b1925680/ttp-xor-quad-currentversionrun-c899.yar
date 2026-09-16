rule TTP_XOR_QUAD_CurrentVersionRun_c899 {
  strings:
    $key_c899 = { 9b f6 [2] bf f8 [2] 94 d4 [2] ba f6 [2] ae ed [2] a1 f7 [2] bf ea [2] bd eb [2] a6 ed [2] ba ea [2] a6 c5 }

  condition:
    any of them
}