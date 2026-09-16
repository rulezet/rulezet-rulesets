rule TTP_XOR_QUAD_CurrentVersionRun_2082 {
  strings:
    $key_2082 = { 73 ed [2] 57 e3 [2] 7c cf [2] 52 ed [2] 46 f6 [2] 49 ec [2] 57 f1 [2] 55 f0 [2] 4e f6 [2] 52 f1 [2] 4e de }

  condition:
    any of them
}