rule TTP_XOR_QUAD_CurrentVersionRun_56e0 {
  strings:
    $key_56e0 = { 05 8f [2] 21 81 [2] 0a ad [2] 24 8f [2] 30 94 [2] 3f 8e [2] 21 93 [2] 23 92 [2] 38 94 [2] 24 93 [2] 38 bc }

  condition:
    any of them
}