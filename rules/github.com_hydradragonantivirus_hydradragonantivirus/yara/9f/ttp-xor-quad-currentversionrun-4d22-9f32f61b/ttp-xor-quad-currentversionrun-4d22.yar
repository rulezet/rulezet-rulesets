rule TTP_XOR_QUAD_CurrentVersionRun_4d22 {
  strings:
    $key_4d22 = { 1e 4d [2] 3a 43 [2] 11 6f [2] 3f 4d [2] 2b 56 [2] 24 4c [2] 3a 51 [2] 38 50 [2] 23 56 [2] 3f 51 [2] 23 7e }

  condition:
    any of them
}