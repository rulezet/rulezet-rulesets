rule TTP_XOR_QUAD_CurrentVersionRun_5782 {
  strings:
    $key_5782 = { 04 ed [2] 20 e3 [2] 0b cf [2] 25 ed [2] 31 f6 [2] 3e ec [2] 20 f1 [2] 22 f0 [2] 39 f6 [2] 25 f1 [2] 39 de }

  condition:
    any of them
}