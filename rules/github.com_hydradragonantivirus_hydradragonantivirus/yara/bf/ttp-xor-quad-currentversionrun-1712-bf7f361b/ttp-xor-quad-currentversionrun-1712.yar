rule TTP_XOR_QUAD_CurrentVersionRun_1712 {
  strings:
    $key_1712 = { 44 7d [2] 60 73 [2] 4b 5f [2] 65 7d [2] 71 66 [2] 7e 7c [2] 60 61 [2] 62 60 [2] 79 66 [2] 65 61 [2] 79 4e }

  condition:
    any of them
}