rule TTP_XOR_QUAD_CurrentVersionRun_1682 {
  strings:
    $key_1682 = { 45 ed [2] 61 e3 [2] 4a cf [2] 64 ed [2] 70 f6 [2] 7f ec [2] 61 f1 [2] 63 f0 [2] 78 f6 [2] 64 f1 [2] 78 de }

  condition:
    any of them
}