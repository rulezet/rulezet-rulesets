rule TTP_XOR_QUAD_CurrentVersionRun_645a {
  strings:
    $key_645a = { 37 35 [2] 13 3b [2] 38 17 [2] 16 35 [2] 02 2e [2] 0d 34 [2] 13 29 [2] 11 28 [2] 0a 2e [2] 16 29 [2] 0a 06 }

  condition:
    any of them
}