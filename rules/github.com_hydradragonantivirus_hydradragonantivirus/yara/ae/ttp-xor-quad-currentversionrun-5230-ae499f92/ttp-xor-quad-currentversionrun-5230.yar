rule TTP_XOR_QUAD_CurrentVersionRun_5230 {
  strings:
    $key_5230 = { 01 5f [2] 25 51 [2] 0e 7d [2] 20 5f [2] 34 44 [2] 3b 5e [2] 25 43 [2] 27 42 [2] 3c 44 [2] 20 43 [2] 3c 6c }

  condition:
    any of them
}