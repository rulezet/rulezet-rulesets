rule TTP_XOR_QUAD_CurrentVersionRun_1400 {
  strings:
    $key_1400 = { 47 6f [2] 63 61 [2] 48 4d [2] 66 6f [2] 72 74 [2] 7d 6e [2] 63 73 [2] 61 72 [2] 7a 74 [2] 66 73 [2] 7a 5c }

  condition:
    any of them
}