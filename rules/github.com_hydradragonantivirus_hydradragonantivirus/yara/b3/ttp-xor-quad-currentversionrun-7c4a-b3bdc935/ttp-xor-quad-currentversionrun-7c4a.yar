rule TTP_XOR_QUAD_CurrentVersionRun_7c4a {
  strings:
    $key_7c4a = { 2f 25 [2] 0b 2b [2] 20 07 [2] 0e 25 [2] 1a 3e [2] 15 24 [2] 0b 39 [2] 09 38 [2] 12 3e [2] 0e 39 [2] 12 16 }

  condition:
    any of them
}