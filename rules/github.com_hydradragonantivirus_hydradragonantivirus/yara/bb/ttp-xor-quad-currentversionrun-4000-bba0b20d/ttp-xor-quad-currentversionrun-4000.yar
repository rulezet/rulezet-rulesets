rule TTP_XOR_QUAD_CurrentVersionRun_4000 {
  strings:
    $key_4000 = { 13 6f [2] 37 61 [2] 1c 4d [2] 32 6f [2] 26 74 [2] 29 6e [2] 37 73 [2] 35 72 [2] 2e 74 [2] 32 73 [2] 2e 5c }

  condition:
    any of them
}