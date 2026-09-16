rule TTP_XOR_QUAD_CurrentVersionRun_7582 {
  strings:
    $key_7582 = { 26 ed [2] 02 e3 [2] 29 cf [2] 07 ed [2] 13 f6 [2] 1c ec [2] 02 f1 [2] 00 f0 [2] 1b f6 [2] 07 f1 [2] 1b de }

  condition:
    any of them
}