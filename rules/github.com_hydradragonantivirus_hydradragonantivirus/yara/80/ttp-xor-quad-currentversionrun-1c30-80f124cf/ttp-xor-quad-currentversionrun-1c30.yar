rule TTP_XOR_QUAD_CurrentVersionRun_1c30 {
  strings:
    $key_1c30 = { 4f 5f [2] 6b 51 [2] 40 7d [2] 6e 5f [2] 7a 44 [2] 75 5e [2] 6b 43 [2] 69 42 [2] 72 44 [2] 6e 43 [2] 72 6c }

  condition:
    any of them
}