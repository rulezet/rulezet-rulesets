rule TTP_XOR_QUAD_CurrentVersionRun_3740 {
  strings:
    $key_3740 = { 64 2f [2] 40 21 [2] 6b 0d [2] 45 2f [2] 51 34 [2] 5e 2e [2] 40 33 [2] 42 32 [2] 59 34 [2] 45 33 [2] 59 1c }

  condition:
    any of them
}