rule TTP_XOR_QUAD_CurrentVersionRun_20b6 {
  strings:
    $key_20b6 = { 73 d9 [2] 57 d7 [2] 7c fb [2] 52 d9 [2] 46 c2 [2] 49 d8 [2] 57 c5 [2] 55 c4 [2] 4e c2 [2] 52 c5 [2] 4e ea }

  condition:
    any of them
}