rule TTP_XOR_QUAD_CurrentVersionRun_2290 {
  strings:
    $key_2290 = { 71 ff [2] 55 f1 [2] 7e dd [2] 50 ff [2] 44 e4 [2] 4b fe [2] 55 e3 [2] 57 e2 [2] 4c e4 [2] 50 e3 [2] 4c cc }

  condition:
    any of them
}