rule TTP_XOR_QUAD_CurrentVersionRun_6812 {
  strings:
    $key_6812 = { 3b 7d [2] 1f 73 [2] 34 5f [2] 1a 7d [2] 0e 66 [2] 01 7c [2] 1f 61 [2] 1d 60 [2] 06 66 [2] 1a 61 [2] 06 4e }

  condition:
    any of them
}