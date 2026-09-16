rule TTP_XOR_QUAD_CurrentVersionRun_7c0a {
  strings:
    $key_7c0a = { 2f 65 [2] 0b 6b [2] 20 47 [2] 0e 65 [2] 1a 7e [2] 15 64 [2] 0b 79 [2] 09 78 [2] 12 7e [2] 0e 79 [2] 12 56 }

  condition:
    any of them
}