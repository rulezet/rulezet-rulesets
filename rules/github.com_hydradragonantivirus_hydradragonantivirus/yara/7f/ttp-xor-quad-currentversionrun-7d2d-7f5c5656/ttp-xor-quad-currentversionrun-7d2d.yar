rule TTP_XOR_QUAD_CurrentVersionRun_7d2d {
  strings:
    $key_7d2d = { 2e 42 [2] 0a 4c [2] 21 60 [2] 0f 42 [2] 1b 59 [2] 14 43 [2] 0a 5e [2] 08 5f [2] 13 59 [2] 0f 5e [2] 13 71 }

  condition:
    any of them
}