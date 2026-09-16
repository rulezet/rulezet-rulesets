rule TTP_XOR_QUAD_CurrentVersionRun_50b6 {
  strings:
    $key_50b6 = { 03 d9 [2] 27 d7 [2] 0c fb [2] 22 d9 [2] 36 c2 [2] 39 d8 [2] 27 c5 [2] 25 c4 [2] 3e c2 [2] 22 c5 [2] 3e ea }

  condition:
    any of them
}