rule TTP_XOR_QUAD_CurrentVersionRun_7682 {
  strings:
    $key_7682 = { 25 ed [2] 01 e3 [2] 2a cf [2] 04 ed [2] 10 f6 [2] 1f ec [2] 01 f1 [2] 03 f0 [2] 18 f6 [2] 04 f1 [2] 18 de }

  condition:
    any of them
}