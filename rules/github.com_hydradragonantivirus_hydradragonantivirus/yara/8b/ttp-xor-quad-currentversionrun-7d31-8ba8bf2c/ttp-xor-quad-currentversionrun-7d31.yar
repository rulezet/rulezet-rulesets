rule TTP_XOR_QUAD_CurrentVersionRun_7d31 {
  strings:
    $key_7d31 = { 2e 5e [2] 0a 50 [2] 21 7c [2] 0f 5e [2] 1b 45 [2] 14 5f [2] 0a 42 [2] 08 43 [2] 13 45 [2] 0f 42 [2] 13 6d }

  condition:
    any of them
}