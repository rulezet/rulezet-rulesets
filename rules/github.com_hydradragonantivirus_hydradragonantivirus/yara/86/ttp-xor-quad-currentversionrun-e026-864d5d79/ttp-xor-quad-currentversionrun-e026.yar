rule TTP_XOR_QUAD_CurrentVersionRun_e026 {
  strings:
    $key_e026 = { b3 49 [2] 97 47 [2] bc 6b [2] 92 49 [2] 86 52 [2] 89 48 [2] 97 55 [2] 95 54 [2] 8e 52 [2] 92 55 [2] 8e 7a }

  condition:
    any of them
}