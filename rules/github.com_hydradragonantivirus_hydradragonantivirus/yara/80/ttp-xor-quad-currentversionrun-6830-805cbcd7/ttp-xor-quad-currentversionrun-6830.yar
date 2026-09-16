rule TTP_XOR_QUAD_CurrentVersionRun_6830 {
  strings:
    $key_6830 = { 3b 5f [2] 1f 51 [2] 34 7d [2] 1a 5f [2] 0e 44 [2] 01 5e [2] 1f 43 [2] 1d 42 [2] 06 44 [2] 1a 43 [2] 06 6c }

  condition:
    any of them
}