rule TTP_XOR_QUAD_CurrentVersionRun_7d62 {
  strings:
    $key_7d62 = { 2e 0d [2] 0a 03 [2] 21 2f [2] 0f 0d [2] 1b 16 [2] 14 0c [2] 0a 11 [2] 08 10 [2] 13 16 [2] 0f 11 [2] 13 3e }

  condition:
    any of them
}