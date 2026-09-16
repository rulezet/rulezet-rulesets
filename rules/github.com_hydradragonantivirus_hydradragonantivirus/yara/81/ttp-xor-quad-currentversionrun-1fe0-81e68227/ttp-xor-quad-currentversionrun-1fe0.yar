rule TTP_XOR_QUAD_CurrentVersionRun_1fe0 {
  strings:
    $key_1fe0 = { 4c 8f [2] 68 81 [2] 43 ad [2] 6d 8f [2] 79 94 [2] 76 8e [2] 68 93 [2] 6a 92 [2] 71 94 [2] 6d 93 [2] 71 bc }

  condition:
    any of them
}