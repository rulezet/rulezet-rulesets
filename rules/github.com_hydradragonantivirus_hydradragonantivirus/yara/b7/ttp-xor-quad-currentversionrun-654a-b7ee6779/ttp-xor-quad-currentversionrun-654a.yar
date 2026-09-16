rule TTP_XOR_QUAD_CurrentVersionRun_654a {
  strings:
    $key_654a = { 36 25 [2] 12 2b [2] 39 07 [2] 17 25 [2] 03 3e [2] 0c 24 [2] 12 39 [2] 10 38 [2] 0b 3e [2] 17 39 [2] 0b 16 }

  condition:
    any of them
}