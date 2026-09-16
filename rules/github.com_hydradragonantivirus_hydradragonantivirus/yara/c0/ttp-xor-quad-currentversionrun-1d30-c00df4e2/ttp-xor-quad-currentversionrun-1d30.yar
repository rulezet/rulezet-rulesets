rule TTP_XOR_QUAD_CurrentVersionRun_1d30 {
  strings:
    $key_1d30 = { 4e 5f [2] 6a 51 [2] 41 7d [2] 6f 5f [2] 7b 44 [2] 74 5e [2] 6a 43 [2] 68 42 [2] 73 44 [2] 6f 43 [2] 73 6c }

  condition:
    any of them
}