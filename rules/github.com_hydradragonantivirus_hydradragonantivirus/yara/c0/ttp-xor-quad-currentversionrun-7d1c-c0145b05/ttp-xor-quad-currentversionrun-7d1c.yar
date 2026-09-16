rule TTP_XOR_QUAD_CurrentVersionRun_7d1c {
  strings:
    $key_7d1c = { 2e 73 [2] 0a 7d [2] 21 51 [2] 0f 73 [2] 1b 68 [2] 14 72 [2] 0a 6f [2] 08 6e [2] 13 68 [2] 0f 6f [2] 13 40 }

  condition:
    any of them
}