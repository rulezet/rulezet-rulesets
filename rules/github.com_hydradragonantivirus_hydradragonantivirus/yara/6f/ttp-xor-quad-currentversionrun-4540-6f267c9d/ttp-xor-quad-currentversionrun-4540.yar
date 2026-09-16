rule TTP_XOR_QUAD_CurrentVersionRun_4540 {
  strings:
    $key_4540 = { 16 2f [2] 32 21 [2] 19 0d [2] 37 2f [2] 23 34 [2] 2c 2e [2] 32 33 [2] 30 32 [2] 2b 34 [2] 37 33 [2] 2b 1c }

  condition:
    any of them
}