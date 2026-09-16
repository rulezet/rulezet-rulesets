rule TTP_XOR_QUAD_CurrentVersionRun_7700 {
  strings:
    $key_7700 = { 24 6f [2] 00 61 [2] 2b 4d [2] 05 6f [2] 11 74 [2] 1e 6e [2] 00 73 [2] 02 72 [2] 19 74 [2] 05 73 [2] 19 5c }

  condition:
    any of them
}