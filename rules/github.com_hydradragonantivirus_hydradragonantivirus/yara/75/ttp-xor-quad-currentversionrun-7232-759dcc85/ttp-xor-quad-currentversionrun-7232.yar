rule TTP_XOR_QUAD_CurrentVersionRun_7232 {
  strings:
    $key_7232 = { 21 5d [2] 05 53 [2] 2e 7f [2] 00 5d [2] 14 46 [2] 1b 5c [2] 05 41 [2] 07 40 [2] 1c 46 [2] 00 41 [2] 1c 6e }

  condition:
    any of them
}