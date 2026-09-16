rule TTP_XOR_QUAD_CurrentVersionRun_0582 {
  strings:
    $key_0582 = { 56 ed [2] 72 e3 [2] 59 cf [2] 77 ed [2] 63 f6 [2] 6c ec [2] 72 f1 [2] 70 f0 [2] 6b f6 [2] 77 f1 [2] 6b de }

  condition:
    any of them
}