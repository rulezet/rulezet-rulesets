rule TTP_XOR_QUAD_CurrentVersionRun_226b {
  strings:
    $key_226b = { 71 04 [2] 55 0a [2] 7e 26 [2] 50 04 [2] 44 1f [2] 4b 05 [2] 55 18 [2] 57 19 [2] 4c 1f [2] 50 18 [2] 4c 37 }

  condition:
    any of them
}