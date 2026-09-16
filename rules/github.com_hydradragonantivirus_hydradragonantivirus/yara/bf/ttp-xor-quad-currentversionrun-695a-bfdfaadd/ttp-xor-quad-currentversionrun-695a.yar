rule TTP_XOR_QUAD_CurrentVersionRun_695a {
  strings:
    $key_695a = { 3a 35 [2] 1e 3b [2] 35 17 [2] 1b 35 [2] 0f 2e [2] 00 34 [2] 1e 29 [2] 1c 28 [2] 07 2e [2] 1b 29 [2] 07 06 }

  condition:
    any of them
}