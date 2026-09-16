rule TTP_XOR_QUAD_CurrentVersionRun_6c60 {
  strings:
    $key_6c60 = { 3f 0f [2] 1b 01 [2] 30 2d [2] 1e 0f [2] 0a 14 [2] 05 0e [2] 1b 13 [2] 19 12 [2] 02 14 [2] 1e 13 [2] 02 3c }

  condition:
    any of them
}