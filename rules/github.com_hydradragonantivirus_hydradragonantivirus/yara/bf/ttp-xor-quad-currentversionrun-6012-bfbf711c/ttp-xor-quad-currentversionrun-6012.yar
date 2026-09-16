rule TTP_XOR_QUAD_CurrentVersionRun_6012 {
  strings:
    $key_6012 = { 33 7d [2] 17 73 [2] 3c 5f [2] 12 7d [2] 06 66 [2] 09 7c [2] 17 61 [2] 15 60 [2] 0e 66 [2] 12 61 [2] 0e 4e }

  condition:
    any of them
}