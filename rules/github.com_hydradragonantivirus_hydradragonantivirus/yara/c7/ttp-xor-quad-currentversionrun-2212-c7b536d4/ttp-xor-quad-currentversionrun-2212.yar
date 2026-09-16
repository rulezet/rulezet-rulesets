rule TTP_XOR_QUAD_CurrentVersionRun_2212 {
  strings:
    $key_2212 = { 71 7d [2] 55 73 [2] 7e 5f [2] 50 7d [2] 44 66 [2] 4b 7c [2] 55 61 [2] 57 60 [2] 4c 66 [2] 50 61 [2] 4c 4e }

  condition:
    any of them
}