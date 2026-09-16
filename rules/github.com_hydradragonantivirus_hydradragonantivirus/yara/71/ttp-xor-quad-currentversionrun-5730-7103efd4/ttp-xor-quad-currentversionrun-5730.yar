rule TTP_XOR_QUAD_CurrentVersionRun_5730 {
  strings:
    $key_5730 = { 04 5f [2] 20 51 [2] 0b 7d [2] 25 5f [2] 31 44 [2] 3e 5e [2] 20 43 [2] 22 42 [2] 39 44 [2] 25 43 [2] 39 6c }

  condition:
    any of them
}