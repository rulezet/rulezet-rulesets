rule TTP_XOR_QUAD_CurrentVersionRun_520a {
  strings:
    $key_520a = { 01 65 [2] 25 6b [2] 0e 47 [2] 20 65 [2] 34 7e [2] 3b 64 [2] 25 79 [2] 27 78 [2] 3c 7e [2] 20 79 [2] 3c 56 }

  condition:
    any of them
}