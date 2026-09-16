rule TTP_XOR_QUAD_CurrentVersionRun_d482 {
  strings:
    $key_d482 = { 87 ed [2] a3 e3 [2] 88 cf [2] a6 ed [2] b2 f6 [2] bd ec [2] a3 f1 [2] a1 f0 [2] ba f6 [2] a6 f1 [2] ba de }

  condition:
    any of them
}