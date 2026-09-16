rule TTP_XOR_QUAD_CurrentVersionRun_6c30 {
  strings:
    $key_6c30 = { 3f 5f [2] 1b 51 [2] 30 7d [2] 1e 5f [2] 0a 44 [2] 05 5e [2] 1b 43 [2] 19 42 [2] 02 44 [2] 1e 43 [2] 02 6c }

  condition:
    any of them
}