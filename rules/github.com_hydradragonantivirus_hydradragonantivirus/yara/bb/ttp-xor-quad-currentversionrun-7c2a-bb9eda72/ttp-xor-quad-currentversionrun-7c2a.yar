rule TTP_XOR_QUAD_CurrentVersionRun_7c2a {
  strings:
    $key_7c2a = { 2f 45 [2] 0b 4b [2] 20 67 [2] 0e 45 [2] 1a 5e [2] 15 44 [2] 0b 59 [2] 09 58 [2] 12 5e [2] 0e 59 [2] 12 76 }

  condition:
    any of them
}