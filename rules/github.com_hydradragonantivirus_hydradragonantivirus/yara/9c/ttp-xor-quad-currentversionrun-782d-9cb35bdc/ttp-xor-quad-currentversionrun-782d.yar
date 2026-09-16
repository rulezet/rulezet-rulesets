rule TTP_XOR_QUAD_CurrentVersionRun_782d {
  strings:
    $key_782d = { 2b 42 [2] 0f 4c [2] 24 60 [2] 0a 42 [2] 1e 59 [2] 11 43 [2] 0f 5e [2] 0d 5f [2] 16 59 [2] 0a 5e [2] 16 71 }

  condition:
    any of them
}