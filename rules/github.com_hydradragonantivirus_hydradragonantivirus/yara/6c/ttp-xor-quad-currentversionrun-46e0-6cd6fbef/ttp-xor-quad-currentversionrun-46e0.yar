rule TTP_XOR_QUAD_CurrentVersionRun_46e0 {
  strings:
    $key_46e0 = { 15 8f [2] 31 81 [2] 1a ad [2] 34 8f [2] 20 94 [2] 2f 8e [2] 31 93 [2] 33 92 [2] 28 94 [2] 34 93 [2] 28 bc }

  condition:
    any of them
}