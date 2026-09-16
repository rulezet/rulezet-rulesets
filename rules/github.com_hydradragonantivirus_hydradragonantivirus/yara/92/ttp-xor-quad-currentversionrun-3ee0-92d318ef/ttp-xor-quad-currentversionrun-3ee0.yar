rule TTP_XOR_QUAD_CurrentVersionRun_3ee0 {
  strings:
    $key_3ee0 = { 6d 8f [2] 49 81 [2] 62 ad [2] 4c 8f [2] 58 94 [2] 57 8e [2] 49 93 [2] 4b 92 [2] 50 94 [2] 4c 93 [2] 50 bc }

  condition:
    any of them
}