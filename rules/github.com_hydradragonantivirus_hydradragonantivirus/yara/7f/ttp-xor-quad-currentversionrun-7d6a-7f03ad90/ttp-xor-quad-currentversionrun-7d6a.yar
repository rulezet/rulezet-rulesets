rule TTP_XOR_QUAD_CurrentVersionRun_7d6a {
  strings:
    $key_7d6a = { 2e 05 [2] 0a 0b [2] 21 27 [2] 0f 05 [2] 1b 1e [2] 14 04 [2] 0a 19 [2] 08 18 [2] 13 1e [2] 0f 19 [2] 13 36 }

  condition:
    any of them
}