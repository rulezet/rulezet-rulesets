rule TTP_XOR_QUAD_CurrentVersionRun_e0b6 {
  strings:
    $key_e0b6 = { b3 d9 [2] 97 d7 [2] bc fb [2] 92 d9 [2] 86 c2 [2] 89 d8 [2] 97 c5 [2] 95 c4 [2] 8e c2 [2] 92 c5 [2] 8e ea }

  condition:
    any of them
}