rule TTP_XOR_QUAD_CurrentVersionRun_5c20 {
  strings:
    $key_5c20 = { 0f 4f [2] 2b 41 [2] 00 6d [2] 2e 4f [2] 3a 54 [2] 35 4e [2] 2b 53 [2] 29 52 [2] 32 54 [2] 2e 53 [2] 32 7c }

  condition:
    any of them
}