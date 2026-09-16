rule TTP_XOR_QUAD_CurrentVersionRun_4e0a {
  strings:
    $key_4e0a = { 1d 65 [2] 39 6b [2] 12 47 [2] 3c 65 [2] 28 7e [2] 27 64 [2] 39 79 [2] 3b 78 [2] 20 7e [2] 3c 79 [2] 20 56 }

  condition:
    any of them
}