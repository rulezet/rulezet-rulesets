rule TTP_XOR_QUAD_CurrentVersionRun_2ce0 {
  strings:
    $key_2ce0 = { 7f 8f [2] 5b 81 [2] 70 ad [2] 5e 8f [2] 4a 94 [2] 45 8e [2] 5b 93 [2] 59 92 [2] 42 94 [2] 5e 93 [2] 42 bc }

  condition:
    any of them
}