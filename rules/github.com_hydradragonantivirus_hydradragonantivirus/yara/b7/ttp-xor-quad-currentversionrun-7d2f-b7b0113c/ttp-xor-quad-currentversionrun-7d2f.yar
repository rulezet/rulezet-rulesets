rule TTP_XOR_QUAD_CurrentVersionRun_7d2f {
  strings:
    $key_7d2f = { 2e 40 [2] 0a 4e [2] 21 62 [2] 0f 40 [2] 1b 5b [2] 14 41 [2] 0a 5c [2] 08 5d [2] 13 5b [2] 0f 5c [2] 13 73 }

  condition:
    any of them
}