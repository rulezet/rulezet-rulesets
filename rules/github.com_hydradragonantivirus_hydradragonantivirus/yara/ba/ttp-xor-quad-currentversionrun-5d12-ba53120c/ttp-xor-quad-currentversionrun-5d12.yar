rule TTP_XOR_QUAD_CurrentVersionRun_5d12 {
  strings:
    $key_5d12 = { 0e 7d [2] 2a 73 [2] 01 5f [2] 2f 7d [2] 3b 66 [2] 34 7c [2] 2a 61 [2] 28 60 [2] 33 66 [2] 2f 61 [2] 33 4e }

  condition:
    any of them
}