rule TTP_XOR_QUAD_CurrentVersionRun_7dfc {
  strings:
    $key_7dfc = { 2e 93 [2] 0a 9d [2] 21 b1 [2] 0f 93 [2] 1b 88 [2] 14 92 [2] 0a 8f [2] 08 8e [2] 13 88 [2] 0f 8f [2] 13 a0 }

  condition:
    any of them
}