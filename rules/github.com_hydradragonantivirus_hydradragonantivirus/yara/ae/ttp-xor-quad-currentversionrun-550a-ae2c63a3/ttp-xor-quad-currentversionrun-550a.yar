rule TTP_XOR_QUAD_CurrentVersionRun_550a {
  strings:
    $key_550a = { 06 65 [2] 22 6b [2] 09 47 [2] 27 65 [2] 33 7e [2] 3c 64 [2] 22 79 [2] 20 78 [2] 3b 7e [2] 27 79 [2] 3b 56 }

  condition:
    any of them
}