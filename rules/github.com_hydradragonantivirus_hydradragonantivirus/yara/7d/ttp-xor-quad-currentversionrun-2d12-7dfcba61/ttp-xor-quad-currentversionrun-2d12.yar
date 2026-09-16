rule TTP_XOR_QUAD_CurrentVersionRun_2d12 {
  strings:
    $key_2d12 = { 7e 7d [2] 5a 73 [2] 71 5f [2] 5f 7d [2] 4b 66 [2] 44 7c [2] 5a 61 [2] 58 60 [2] 43 66 [2] 5f 61 [2] 43 4e }

  condition:
    any of them
}