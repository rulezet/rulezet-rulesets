rule TTP_XOR_QUAD_CurrentVersionRun_0973 {
  strings:
    $key_0973 = { 5a 1c [2] 7e 12 [2] 55 3e [2] 7b 1c [2] 6f 07 [2] 60 1d [2] 7e 00 [2] 7c 01 [2] 67 07 [2] 7b 00 [2] 67 2f }

  condition:
    any of them
}