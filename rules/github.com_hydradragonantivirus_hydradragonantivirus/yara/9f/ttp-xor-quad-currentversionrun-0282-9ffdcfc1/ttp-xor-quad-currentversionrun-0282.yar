rule TTP_XOR_QUAD_CurrentVersionRun_0282 {
  strings:
    $key_0282 = { 51 ed [2] 75 e3 [2] 5e cf [2] 70 ed [2] 64 f6 [2] 6b ec [2] 75 f1 [2] 77 f0 [2] 6c f6 [2] 70 f1 [2] 6c de }

  condition:
    any of them
}