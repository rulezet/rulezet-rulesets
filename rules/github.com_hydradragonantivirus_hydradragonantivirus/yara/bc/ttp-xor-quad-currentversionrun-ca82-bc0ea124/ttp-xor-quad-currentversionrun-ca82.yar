rule TTP_XOR_QUAD_CurrentVersionRun_ca82 {
  strings:
    $key_ca82 = { 99 ed [2] bd e3 [2] 96 cf [2] b8 ed [2] ac f6 [2] a3 ec [2] bd f1 [2] bf f0 [2] a4 f6 [2] b8 f1 [2] a4 de }

  condition:
    any of them
}