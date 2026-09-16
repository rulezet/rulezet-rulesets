rule TTP_XOR_QUAD_CurrentVersionRun_5c11 {
  strings:
    $key_5c11 = { 0f 7e [2] 2b 70 [2] 00 5c [2] 2e 7e [2] 3a 65 [2] 35 7f [2] 2b 62 [2] 29 63 [2] 32 65 [2] 2e 62 [2] 32 4d }

  condition:
    any of them
}