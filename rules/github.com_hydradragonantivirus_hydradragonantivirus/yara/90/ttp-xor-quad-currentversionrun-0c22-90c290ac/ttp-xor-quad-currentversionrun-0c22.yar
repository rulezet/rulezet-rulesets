rule TTP_XOR_QUAD_CurrentVersionRun_0c22 {
  strings:
    $key_0c22 = { 5f 4d [2] 7b 43 [2] 50 6f [2] 7e 4d [2] 6a 56 [2] 65 4c [2] 7b 51 [2] 79 50 [2] 62 56 [2] 7e 51 [2] 62 7e }

  condition:
    any of them
}