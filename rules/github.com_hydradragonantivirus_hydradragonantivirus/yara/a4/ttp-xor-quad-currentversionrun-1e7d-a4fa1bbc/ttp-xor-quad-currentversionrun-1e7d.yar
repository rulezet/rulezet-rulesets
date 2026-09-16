rule TTP_XOR_QUAD_CurrentVersionRun_1e7d {
  strings:
    $key_1e7d = { 4d 12 [2] 69 1c [2] 42 30 [2] 6c 12 [2] 78 09 [2] 77 13 [2] 69 0e [2] 6b 0f [2] 70 09 [2] 6c 0e [2] 70 21 }

  condition:
    any of them
}