rule TTP_XOR_QUAD_CurrentVersionRun_4712 {
  strings:
    $key_4712 = { 14 7d [2] 30 73 [2] 1b 5f [2] 35 7d [2] 21 66 [2] 2e 7c [2] 30 61 [2] 32 60 [2] 29 66 [2] 35 61 [2] 29 4e }

  condition:
    any of them
}