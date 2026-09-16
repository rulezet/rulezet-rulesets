rule TTP_XOR_QUAD_CurrentVersionRun_25e0 {
  strings:
    $key_25e0 = { 76 8f [2] 52 81 [2] 79 ad [2] 57 8f [2] 43 94 [2] 4c 8e [2] 52 93 [2] 50 92 [2] 4b 94 [2] 57 93 [2] 4b bc }

  condition:
    any of them
}