rule TTP_XOR_QUAD_CurrentVersionRun_7d48 {
  strings:
    $key_7d48 = { 2e 27 [2] 0a 29 [2] 21 05 [2] 0f 27 [2] 1b 3c [2] 14 26 [2] 0a 3b [2] 08 3a [2] 13 3c [2] 0f 3b [2] 13 14 }

  condition:
    any of them
}