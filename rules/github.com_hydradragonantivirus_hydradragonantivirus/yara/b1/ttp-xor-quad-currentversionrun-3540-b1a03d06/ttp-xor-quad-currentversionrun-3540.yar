rule TTP_XOR_QUAD_CurrentVersionRun_3540 {
  strings:
    $key_3540 = { 66 2f [2] 42 21 [2] 69 0d [2] 47 2f [2] 53 34 [2] 5c 2e [2] 42 33 [2] 40 32 [2] 5b 34 [2] 47 33 [2] 5b 1c }

  condition:
    any of them
}