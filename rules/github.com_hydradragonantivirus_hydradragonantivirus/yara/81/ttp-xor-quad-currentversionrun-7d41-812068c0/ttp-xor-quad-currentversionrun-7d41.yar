rule TTP_XOR_QUAD_CurrentVersionRun_7d41 {
  strings:
    $key_7d41 = { 2e 2e [2] 0a 20 [2] 21 0c [2] 0f 2e [2] 1b 35 [2] 14 2f [2] 0a 32 [2] 08 33 [2] 13 35 [2] 0f 32 [2] 13 1d }

  condition:
    any of them
}