rule TTP_XOR_QUAD_CurrentVersionRun_3ce0 {
  strings:
    $key_3ce0 = { 6f 8f [2] 4b 81 [2] 60 ad [2] 4e 8f [2] 5a 94 [2] 55 8e [2] 4b 93 [2] 49 92 [2] 52 94 [2] 4e 93 [2] 52 bc }

  condition:
    any of them
}