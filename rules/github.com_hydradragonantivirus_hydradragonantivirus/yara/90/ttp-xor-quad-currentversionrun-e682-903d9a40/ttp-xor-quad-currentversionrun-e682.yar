rule TTP_XOR_QUAD_CurrentVersionRun_e682 {
  strings:
    $key_e682 = { b5 ed [2] 91 e3 [2] ba cf [2] 94 ed [2] 80 f6 [2] 8f ec [2] 91 f1 [2] 93 f0 [2] 88 f6 [2] 94 f1 [2] 88 de }

  condition:
    any of them
}