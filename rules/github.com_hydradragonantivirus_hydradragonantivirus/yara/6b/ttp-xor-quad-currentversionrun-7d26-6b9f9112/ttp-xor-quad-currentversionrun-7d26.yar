rule TTP_XOR_QUAD_CurrentVersionRun_7d26 {
  strings:
    $key_7d26 = { 2e 49 [2] 0a 47 [2] 21 6b [2] 0f 49 [2] 1b 52 [2] 14 48 [2] 0a 55 [2] 08 54 [2] 13 52 [2] 0f 55 [2] 13 7a }

  condition:
    any of them
}