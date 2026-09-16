rule TTP_XOR_QUAD_CurrentVersionRun_1d12 {
  strings:
    $key_1d12 = { 4e 7d [2] 6a 73 [2] 41 5f [2] 6f 7d [2] 7b 66 [2] 74 7c [2] 6a 61 [2] 68 60 [2] 73 66 [2] 6f 61 [2] 73 4e }

  condition:
    any of them
}