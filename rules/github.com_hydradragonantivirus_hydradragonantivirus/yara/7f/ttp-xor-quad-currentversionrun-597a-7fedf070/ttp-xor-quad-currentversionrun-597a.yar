rule TTP_XOR_QUAD_CurrentVersionRun_597a {
  strings:
    $key_597a = { 0a 15 [2] 2e 1b [2] 05 37 [2] 2b 15 [2] 3f 0e [2] 30 14 [2] 2e 09 [2] 2c 08 [2] 37 0e [2] 2b 09 [2] 37 26 }

  condition:
    any of them
}