rule TTP_XOR_QUAD_CurrentVersionRun_4022 {
  strings:
    $key_4022 = { 13 4d [2] 37 43 [2] 1c 6f [2] 32 4d [2] 26 56 [2] 29 4c [2] 37 51 [2] 35 50 [2] 2e 56 [2] 32 51 [2] 2e 7e }

  condition:
    any of them
}