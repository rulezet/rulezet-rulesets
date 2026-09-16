rule TTP_XOR_QUAD_CurrentVersionRun_7622 {
  strings:
    $key_7622 = { 25 4d [2] 01 43 [2] 2a 6f [2] 04 4d [2] 10 56 [2] 1f 4c [2] 01 51 [2] 03 50 [2] 18 56 [2] 04 51 [2] 18 7e }

  condition:
    any of them
}