rule TTP_XOR_QUAD_CurrentVersionRun_77e0 {
  strings:
    $key_77e0 = { 24 8f [2] 00 81 [2] 2b ad [2] 05 8f [2] 11 94 [2] 1e 8e [2] 00 93 [2] 02 92 [2] 19 94 [2] 05 93 [2] 19 bc }

  condition:
    any of them
}