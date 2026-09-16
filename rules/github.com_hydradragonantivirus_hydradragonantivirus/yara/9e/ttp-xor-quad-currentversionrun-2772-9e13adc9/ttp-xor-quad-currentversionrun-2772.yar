rule TTP_XOR_QUAD_CurrentVersionRun_2772 {
  strings:
    $key_2772 = { 74 1d [2] 50 13 [2] 7b 3f [2] 55 1d [2] 41 06 [2] 4e 1c [2] 50 01 [2] 52 00 [2] 49 06 [2] 55 01 [2] 49 2e }

  condition:
    any of them
}