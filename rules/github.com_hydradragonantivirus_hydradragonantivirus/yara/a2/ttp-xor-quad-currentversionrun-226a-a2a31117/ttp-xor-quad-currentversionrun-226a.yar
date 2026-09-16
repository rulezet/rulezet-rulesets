rule TTP_XOR_QUAD_CurrentVersionRun_226a {
  strings:
    $key_226a = { 71 05 [2] 55 0b [2] 7e 27 [2] 50 05 [2] 44 1e [2] 4b 04 [2] 55 19 [2] 57 18 [2] 4c 1e [2] 50 19 [2] 4c 36 }

  condition:
    any of them
}