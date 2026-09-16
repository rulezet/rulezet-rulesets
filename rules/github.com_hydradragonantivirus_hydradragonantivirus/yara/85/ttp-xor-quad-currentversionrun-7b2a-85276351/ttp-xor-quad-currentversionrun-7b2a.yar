rule TTP_XOR_QUAD_CurrentVersionRun_7b2a {
  strings:
    $key_7b2a = { 28 45 [2] 0c 4b [2] 27 67 [2] 09 45 [2] 1d 5e [2] 12 44 [2] 0c 59 [2] 0e 58 [2] 15 5e [2] 09 59 [2] 15 76 }

  condition:
    any of them
}