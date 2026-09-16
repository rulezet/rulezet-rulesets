rule TTP_XOR_QUAD_CurrentVersionRun_0730 {
  strings:
    $key_0730 = { 54 5f [2] 70 51 [2] 5b 7d [2] 75 5f [2] 61 44 [2] 6e 5e [2] 70 43 [2] 72 42 [2] 69 44 [2] 75 43 [2] 69 6c }

  condition:
    any of them
}