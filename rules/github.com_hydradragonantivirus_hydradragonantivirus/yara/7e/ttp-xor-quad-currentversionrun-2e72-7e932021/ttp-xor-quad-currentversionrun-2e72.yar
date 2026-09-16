rule TTP_XOR_QUAD_CurrentVersionRun_2e72 {
  strings:
    $key_2e72 = { 7d 1d [2] 59 13 [2] 72 3f [2] 5c 1d [2] 48 06 [2] 47 1c [2] 59 01 [2] 5b 00 [2] 40 06 [2] 5c 01 [2] 40 2e }

  condition:
    any of them
}