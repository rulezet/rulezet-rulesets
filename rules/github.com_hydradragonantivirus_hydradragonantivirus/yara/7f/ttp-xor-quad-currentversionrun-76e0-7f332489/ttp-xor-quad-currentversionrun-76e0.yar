rule TTP_XOR_QUAD_CurrentVersionRun_76e0 {
  strings:
    $key_76e0 = { 25 8f [2] 01 81 [2] 2a ad [2] 04 8f [2] 10 94 [2] 1f 8e [2] 01 93 [2] 03 92 [2] 18 94 [2] 04 93 [2] 18 bc }

  condition:
    any of them
}