rule TTP_XOR_QUAD_CurrentVersionRun_7d6c {
  strings:
    $key_7d6c = { 2e 03 [2] 0a 0d [2] 21 21 [2] 0f 03 [2] 1b 18 [2] 14 02 [2] 0a 1f [2] 08 1e [2] 13 18 [2] 0f 1f [2] 13 30 }

  condition:
    any of them
}