rule TTP_XOR_QUAD_CurrentVersionRun_7860 {
  strings:
    $key_7860 = { 2b 0f [2] 0f 01 [2] 24 2d [2] 0a 0f [2] 1e 14 [2] 11 0e [2] 0f 13 [2] 0d 12 [2] 16 14 [2] 0a 13 [2] 16 3c }

  condition:
    any of them
}