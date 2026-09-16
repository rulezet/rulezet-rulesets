rule TTP_XOR_QUAD_CurrentVersionRun_7d63 {
  strings:
    $key_7d63 = { 2e 0c [2] 0a 02 [2] 21 2e [2] 0f 0c [2] 1b 17 [2] 14 0d [2] 0a 10 [2] 08 11 [2] 13 17 [2] 0f 10 [2] 13 3f }

  condition:
    any of them
}