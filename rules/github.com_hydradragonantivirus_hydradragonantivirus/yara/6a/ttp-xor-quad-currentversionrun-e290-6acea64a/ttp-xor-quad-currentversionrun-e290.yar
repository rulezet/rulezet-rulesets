rule TTP_XOR_QUAD_CurrentVersionRun_e290 {
  strings:
    $key_e290 = { b1 ff [2] 95 f1 [2] be dd [2] 90 ff [2] 84 e4 [2] 8b fe [2] 95 e3 [2] 97 e2 [2] 8c e4 [2] 90 e3 [2] 8c cc }

  condition:
    any of them
}