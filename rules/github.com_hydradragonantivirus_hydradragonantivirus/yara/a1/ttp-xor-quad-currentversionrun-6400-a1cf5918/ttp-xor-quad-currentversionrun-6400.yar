rule TTP_XOR_QUAD_CurrentVersionRun_6400 {
  strings:
    $key_6400 = { 37 6f [2] 13 61 [2] 38 4d [2] 16 6f [2] 02 74 [2] 0d 6e [2] 13 73 [2] 11 72 [2] 0a 74 [2] 16 73 [2] 0a 5c }

  condition:
    any of them
}