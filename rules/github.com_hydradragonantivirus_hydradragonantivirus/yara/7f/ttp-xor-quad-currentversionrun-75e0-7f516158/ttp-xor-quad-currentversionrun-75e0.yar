rule TTP_XOR_QUAD_CurrentVersionRun_75e0 {
  strings:
    $key_75e0 = { 26 8f [2] 02 81 [2] 29 ad [2] 07 8f [2] 13 94 [2] 1c 8e [2] 02 93 [2] 00 92 [2] 1b 94 [2] 07 93 [2] 1b bc }

  condition:
    any of them
}