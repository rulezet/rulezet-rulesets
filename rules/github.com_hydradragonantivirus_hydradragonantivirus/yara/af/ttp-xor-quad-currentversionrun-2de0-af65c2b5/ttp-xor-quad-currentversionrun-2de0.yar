rule TTP_XOR_QUAD_CurrentVersionRun_2de0 {
  strings:
    $key_2de0 = { 7e 8f [2] 5a 81 [2] 71 ad [2] 5f 8f [2] 4b 94 [2] 44 8e [2] 5a 93 [2] 58 92 [2] 43 94 [2] 5f 93 [2] 43 bc }

  condition:
    any of them
}