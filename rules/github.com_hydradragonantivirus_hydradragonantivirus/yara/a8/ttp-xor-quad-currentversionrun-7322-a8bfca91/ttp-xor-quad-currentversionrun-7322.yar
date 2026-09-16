rule TTP_XOR_QUAD_CurrentVersionRun_7322 {
  strings:
    $key_7322 = { 20 4d [2] 04 43 [2] 2f 6f [2] 01 4d [2] 15 56 [2] 1a 4c [2] 04 51 [2] 06 50 [2] 1d 56 [2] 01 51 [2] 1d 7e }

  condition:
    any of them
}