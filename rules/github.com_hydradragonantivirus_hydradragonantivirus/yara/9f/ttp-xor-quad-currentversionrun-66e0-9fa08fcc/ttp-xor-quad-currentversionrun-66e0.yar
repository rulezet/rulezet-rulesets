rule TTP_XOR_QUAD_CurrentVersionRun_66e0 {
  strings:
    $key_66e0 = { 35 8f [2] 11 81 [2] 3a ad [2] 14 8f [2] 00 94 [2] 0f 8e [2] 11 93 [2] 13 92 [2] 08 94 [2] 14 93 [2] 08 bc }

  condition:
    any of them
}