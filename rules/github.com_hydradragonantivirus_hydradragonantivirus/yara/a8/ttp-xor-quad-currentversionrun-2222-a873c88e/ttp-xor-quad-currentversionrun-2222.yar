rule TTP_XOR_QUAD_CurrentVersionRun_2222 {
  strings:
    $key_2222 = { 71 4d [2] 55 43 [2] 7e 6f [2] 50 4d [2] 44 56 [2] 4b 4c [2] 55 51 [2] 57 50 [2] 4c 56 [2] 50 51 [2] 4c 7e }

  condition:
    any of them
}