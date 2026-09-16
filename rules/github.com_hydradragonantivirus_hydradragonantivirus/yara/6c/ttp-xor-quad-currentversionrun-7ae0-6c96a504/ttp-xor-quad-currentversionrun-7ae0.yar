rule TTP_XOR_QUAD_CurrentVersionRun_7ae0 {
  strings:
    $key_7ae0 = { 29 8f [2] 0d 81 [2] 26 ad [2] 08 8f [2] 1c 94 [2] 13 8e [2] 0d 93 [2] 0f 92 [2] 14 94 [2] 08 93 [2] 14 bc }

  condition:
    any of them
}