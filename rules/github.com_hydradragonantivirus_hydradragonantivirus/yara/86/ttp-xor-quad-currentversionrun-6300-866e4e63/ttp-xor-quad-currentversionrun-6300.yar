rule TTP_XOR_QUAD_CurrentVersionRun_6300 {
  strings:
    $key_6300 = { 30 6f [2] 14 61 [2] 3f 4d [2] 11 6f [2] 05 74 [2] 0a 6e [2] 14 73 [2] 16 72 [2] 0d 74 [2] 11 73 [2] 0d 5c }

  condition:
    any of them
}