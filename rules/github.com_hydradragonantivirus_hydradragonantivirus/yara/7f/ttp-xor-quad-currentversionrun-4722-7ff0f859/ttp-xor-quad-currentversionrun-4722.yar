rule TTP_XOR_QUAD_CurrentVersionRun_4722 {
  strings:
    $key_4722 = { 14 4d [2] 30 43 [2] 1b 6f [2] 35 4d [2] 21 56 [2] 2e 4c [2] 30 51 [2] 32 50 [2] 29 56 [2] 35 51 [2] 29 7e }

  condition:
    any of them
}