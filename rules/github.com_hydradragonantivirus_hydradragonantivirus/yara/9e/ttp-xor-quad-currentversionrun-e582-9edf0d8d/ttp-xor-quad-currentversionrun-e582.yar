rule TTP_XOR_QUAD_CurrentVersionRun_e582 {
  strings:
    $key_e582 = { b6 ed [2] 92 e3 [2] b9 cf [2] 97 ed [2] 83 f6 [2] 8c ec [2] 92 f1 [2] 90 f0 [2] 8b f6 [2] 97 f1 [2] 8b de }

  condition:
    any of them
}