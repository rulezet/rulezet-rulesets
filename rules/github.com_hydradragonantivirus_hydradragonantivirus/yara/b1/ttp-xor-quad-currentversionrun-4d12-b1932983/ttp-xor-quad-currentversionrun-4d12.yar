rule TTP_XOR_QUAD_CurrentVersionRun_4d12 {
  strings:
    $key_4d12 = { 1e 7d [2] 3a 73 [2] 11 5f [2] 3f 7d [2] 2b 66 [2] 24 7c [2] 3a 61 [2] 38 60 [2] 23 66 [2] 3f 61 [2] 23 4e }

  condition:
    any of them
}