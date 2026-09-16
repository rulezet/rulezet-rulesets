rule TTP_XOR_QUAD_CurrentVersionRun_7d4c {
  strings:
    $key_7d4c = { 2e 23 [2] 0a 2d [2] 21 01 [2] 0f 23 [2] 1b 38 [2] 14 22 [2] 0a 3f [2] 08 3e [2] 13 38 [2] 0f 3f [2] 13 10 }

  condition:
    any of them
}