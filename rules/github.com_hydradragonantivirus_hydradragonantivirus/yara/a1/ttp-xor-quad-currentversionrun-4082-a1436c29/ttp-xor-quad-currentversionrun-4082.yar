rule TTP_XOR_QUAD_CurrentVersionRun_4082 {
  strings:
    $key_4082 = { 13 ed [2] 37 e3 [2] 1c cf [2] 32 ed [2] 26 f6 [2] 29 ec [2] 37 f1 [2] 35 f0 [2] 2e f6 [2] 32 f1 [2] 2e de }

  condition:
    any of them
}