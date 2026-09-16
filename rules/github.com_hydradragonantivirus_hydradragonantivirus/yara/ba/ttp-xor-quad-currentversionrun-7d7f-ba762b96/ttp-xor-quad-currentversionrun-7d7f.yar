rule TTP_XOR_QUAD_CurrentVersionRun_7d7f {
  strings:
    $key_7d7f = { 2e 10 [2] 0a 1e [2] 21 32 [2] 0f 10 [2] 1b 0b [2] 14 11 [2] 0a 0c [2] 08 0d [2] 13 0b [2] 0f 0c [2] 13 23 }

  condition:
    any of them
}