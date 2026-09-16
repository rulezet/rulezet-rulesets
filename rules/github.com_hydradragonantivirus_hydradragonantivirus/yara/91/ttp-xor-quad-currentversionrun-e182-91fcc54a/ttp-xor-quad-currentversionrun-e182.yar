rule TTP_XOR_QUAD_CurrentVersionRun_e182 {
  strings:
    $key_e182 = { b2 ed [2] 96 e3 [2] bd cf [2] 93 ed [2] 87 f6 [2] 88 ec [2] 96 f1 [2] 94 f0 [2] 8f f6 [2] 93 f1 [2] 8f de }

  condition:
    any of them
}