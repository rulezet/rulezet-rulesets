rule TTP_XOR_QUAD_CurrentVersionRun_e030 {
  strings:
    $key_e030 = { b3 5f [2] 97 51 [2] bc 7d [2] 92 5f [2] 86 44 [2] 89 5e [2] 97 43 [2] 95 42 [2] 8e 44 [2] 92 43 [2] 8e 6c }

  condition:
    any of them
}