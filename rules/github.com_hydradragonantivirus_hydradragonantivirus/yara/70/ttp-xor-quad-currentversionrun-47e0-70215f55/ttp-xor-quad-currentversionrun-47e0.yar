rule TTP_XOR_QUAD_CurrentVersionRun_47e0 {
  strings:
    $key_47e0 = { 14 8f [2] 30 81 [2] 1b ad [2] 35 8f [2] 21 94 [2] 2e 8e [2] 30 93 [2] 32 92 [2] 29 94 [2] 35 93 [2] 29 bc }

  condition:
    any of them
}