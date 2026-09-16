rule TTP_XOR_QUAD_CurrentVersionRun_7022 {
  strings:
    $key_7022 = { 23 4d [2] 07 43 [2] 2c 6f [2] 02 4d [2] 16 56 [2] 19 4c [2] 07 51 [2] 05 50 [2] 1e 56 [2] 02 51 [2] 1e 7e }

  condition:
    any of them
}