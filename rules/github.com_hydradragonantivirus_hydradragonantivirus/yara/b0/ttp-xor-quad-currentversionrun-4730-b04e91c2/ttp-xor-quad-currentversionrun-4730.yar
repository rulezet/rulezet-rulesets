rule TTP_XOR_QUAD_CurrentVersionRun_4730 {
  strings:
    $key_4730 = { 14 5f [2] 30 51 [2] 1b 7d [2] 35 5f [2] 21 44 [2] 2e 5e [2] 30 43 [2] 32 42 [2] 29 44 [2] 35 43 [2] 29 6c }

  condition:
    any of them
}