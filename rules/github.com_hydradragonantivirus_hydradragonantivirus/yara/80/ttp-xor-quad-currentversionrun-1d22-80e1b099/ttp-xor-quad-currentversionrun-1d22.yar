rule TTP_XOR_QUAD_CurrentVersionRun_1d22 {
  strings:
    $key_1d22 = { 4e 4d [2] 6a 43 [2] 41 6f [2] 6f 4d [2] 7b 56 [2] 74 4c [2] 6a 51 [2] 68 50 [2] 73 56 [2] 6f 51 [2] 73 7e }

  condition:
    any of them
}