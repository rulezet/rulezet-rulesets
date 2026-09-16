rule TTP_XOR_QUAD_CurrentVersionRun_2512 {
  strings:
    $key_2512 = { 76 7d [2] 52 73 [2] 79 5f [2] 57 7d [2] 43 66 [2] 4c 7c [2] 52 61 [2] 50 60 [2] 4b 66 [2] 57 61 [2] 4b 4e }

  condition:
    any of them
}