rule TTP_XOR_QUAD_CurrentVersionRun_45e0 {
  strings:
    $key_45e0 = { 16 8f [2] 32 81 [2] 19 ad [2] 37 8f [2] 23 94 [2] 2c 8e [2] 32 93 [2] 30 92 [2] 2b 94 [2] 37 93 [2] 2b bc }

  condition:
    any of them
}