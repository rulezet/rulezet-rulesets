rule TTP_XOR_QUAD_CurrentVersionRun_e0d2 {
  strings:
    $key_e0d2 = { b3 bd [2] 97 b3 [2] bc 9f [2] 92 bd [2] 86 a6 [2] 89 bc [2] 97 a1 [2] 95 a0 [2] 8e a6 [2] 92 a1 [2] 8e 8e }

  condition:
    any of them
}