rule TTP_XOR_QUAD_CurrentVersionRun_1d1d {
  strings:
    $key_1d1d = { 4e 72 [2] 6a 7c [2] 41 50 [2] 6f 72 [2] 7b 69 [2] 74 73 [2] 6a 6e [2] 68 6f [2] 73 69 [2] 6f 6e [2] 73 41 }

  condition:
    any of them
}