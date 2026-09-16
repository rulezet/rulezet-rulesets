rule TTP_XOR_QUAD_CurrentVersionRun_0e72 {
  strings:
    $key_0e72 = { 5d 1d [2] 79 13 [2] 52 3f [2] 7c 1d [2] 68 06 [2] 67 1c [2] 79 01 [2] 7b 00 [2] 60 06 [2] 7c 01 [2] 60 2e }

  condition:
    any of them
}