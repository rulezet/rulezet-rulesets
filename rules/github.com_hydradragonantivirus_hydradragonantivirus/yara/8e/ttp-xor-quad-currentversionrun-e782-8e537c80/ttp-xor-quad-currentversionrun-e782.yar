rule TTP_XOR_QUAD_CurrentVersionRun_e782 {
  strings:
    $key_e782 = { b4 ed [2] 90 e3 [2] bb cf [2] 95 ed [2] 81 f6 [2] 8e ec [2] 90 f1 [2] 92 f0 [2] 89 f6 [2] 95 f1 [2] 89 de }

  condition:
    any of them
}