rule TTP_XOR_QUAD_CurrentVersionRun_600a {
  strings:
    $key_600a = { 33 65 [2] 17 6b [2] 3c 47 [2] 12 65 [2] 06 7e [2] 09 64 [2] 17 79 [2] 15 78 [2] 0e 7e [2] 12 79 [2] 0e 56 }

  condition:
    any of them
}