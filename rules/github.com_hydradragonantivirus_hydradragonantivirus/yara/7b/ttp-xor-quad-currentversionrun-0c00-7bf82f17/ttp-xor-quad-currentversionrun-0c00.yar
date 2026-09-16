rule TTP_XOR_QUAD_CurrentVersionRun_0c00 {
  strings:
    $key_0c00 = { 5f 6f [2] 7b 61 [2] 50 4d [2] 7e 6f [2] 6a 74 [2] 65 6e [2] 7b 73 [2] 79 72 [2] 62 74 [2] 7e 73 [2] 62 5c }

  condition:
    any of them
}