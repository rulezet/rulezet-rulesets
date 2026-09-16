rule TTP_XOR_QUAD_CurrentVersionRun_1d00 {
  strings:
    $key_1d00 = { 4e 6f [2] 6a 61 [2] 41 4d [2] 6f 6f [2] 7b 74 [2] 74 6e [2] 6a 73 [2] 68 72 [2] 73 74 [2] 6f 73 [2] 73 5c }

  condition:
    any of them
}