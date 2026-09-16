rule TTP_XOR_QUAD_CurrentVersionRun_5a30 {
  strings:
    $key_5a30 = { 09 5f [2] 2d 51 [2] 06 7d [2] 28 5f [2] 3c 44 [2] 33 5e [2] 2d 43 [2] 2f 42 [2] 34 44 [2] 28 43 [2] 34 6c }

  condition:
    any of them
}