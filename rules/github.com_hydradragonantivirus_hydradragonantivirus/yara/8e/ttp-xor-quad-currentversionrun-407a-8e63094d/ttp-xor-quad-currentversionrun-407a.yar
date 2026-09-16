rule TTP_XOR_QUAD_CurrentVersionRun_407a {
  strings:
    $key_407a = { 13 15 [2] 37 1b [2] 1c 37 [2] 32 15 [2] 26 0e [2] 29 14 [2] 37 09 [2] 35 08 [2] 2e 0e [2] 32 09 [2] 2e 26 }

  condition:
    any of them
}