rule TTP_XOR_QUAD_CurrentVersionRun_3c22 {
  strings:
    $key_3c22 = { 6f 4d [2] 4b 43 [2] 60 6f [2] 4e 4d [2] 5a 56 [2] 55 4c [2] 4b 51 [2] 49 50 [2] 52 56 [2] 4e 51 [2] 52 7e }

  condition:
    any of them
}