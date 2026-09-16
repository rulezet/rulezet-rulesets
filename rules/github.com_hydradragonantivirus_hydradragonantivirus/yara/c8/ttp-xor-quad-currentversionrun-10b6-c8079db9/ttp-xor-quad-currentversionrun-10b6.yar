rule TTP_XOR_QUAD_CurrentVersionRun_10b6 {
  strings:
    $key_10b6 = { 43 d9 [2] 67 d7 [2] 4c fb [2] 62 d9 [2] 76 c2 [2] 79 d8 [2] 67 c5 [2] 65 c4 [2] 7e c2 [2] 62 c5 [2] 7e ea }

  condition:
    any of them
}