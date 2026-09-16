rule TTP_XOR_QUAD_CurrentVersionRun_6f0a {
  strings:
    $key_6f0a = { 3c 65 [2] 18 6b [2] 33 47 [2] 1d 65 [2] 09 7e [2] 06 64 [2] 18 79 [2] 1a 78 [2] 01 7e [2] 1d 79 [2] 01 56 }

  condition:
    any of them
}