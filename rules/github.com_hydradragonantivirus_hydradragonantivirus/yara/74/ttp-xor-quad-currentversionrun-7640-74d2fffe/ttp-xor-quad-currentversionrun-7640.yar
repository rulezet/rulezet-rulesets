rule TTP_XOR_QUAD_CurrentVersionRun_7640 {
  strings:
    $key_7640 = { 25 2f [2] 01 21 [2] 2a 0d [2] 04 2f [2] 10 34 [2] 1f 2e [2] 01 33 [2] 03 32 [2] 18 34 [2] 04 33 [2] 18 1c }

  condition:
    any of them
}