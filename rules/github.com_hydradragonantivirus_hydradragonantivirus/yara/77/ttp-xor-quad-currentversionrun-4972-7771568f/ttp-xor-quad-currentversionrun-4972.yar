rule TTP_XOR_QUAD_CurrentVersionRun_4972 {
  strings:
    $key_4972 = { 1a 1d [2] 3e 13 [2] 15 3f [2] 3b 1d [2] 2f 06 [2] 20 1c [2] 3e 01 [2] 3c 00 [2] 27 06 [2] 3b 01 [2] 27 2e }

  condition:
    any of them
}