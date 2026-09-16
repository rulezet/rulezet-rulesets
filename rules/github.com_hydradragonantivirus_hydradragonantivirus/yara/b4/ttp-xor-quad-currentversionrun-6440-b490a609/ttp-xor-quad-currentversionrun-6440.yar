rule TTP_XOR_QUAD_CurrentVersionRun_6440 {
  strings:
    $key_6440 = { 37 2f [2] 13 21 [2] 38 0d [2] 16 2f [2] 02 34 [2] 0d 2e [2] 13 33 [2] 11 32 [2] 0a 34 [2] 16 33 [2] 0a 1c }

  condition:
    any of them
}