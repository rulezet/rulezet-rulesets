rule TTP_XOR_QUAD_CurrentVersionRun_3122 {
  strings:
    $key_3122 = { 62 4d [2] 46 43 [2] 6d 6f [2] 43 4d [2] 57 56 [2] 58 4c [2] 46 51 [2] 44 50 [2] 5f 56 [2] 43 51 [2] 5f 7e }

  condition:
    any of them
}