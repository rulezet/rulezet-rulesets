rule TTP_XOR_QUAD_CurrentVersionRun_06e0 {
  strings:
    $key_06e0 = { 55 8f [2] 71 81 [2] 5a ad [2] 74 8f [2] 60 94 [2] 6f 8e [2] 71 93 [2] 73 92 [2] 68 94 [2] 74 93 [2] 68 bc }

  condition:
    any of them
}