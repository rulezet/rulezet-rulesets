rule TTP_XOR_QUAD_CurrentVersionRun_7b12 {
  strings:
    $key_7b12 = { 28 7d [2] 0c 73 [2] 27 5f [2] 09 7d [2] 1d 66 [2] 12 7c [2] 0c 61 [2] 0e 60 [2] 15 66 [2] 09 61 [2] 15 4e }

  condition:
    any of them
}