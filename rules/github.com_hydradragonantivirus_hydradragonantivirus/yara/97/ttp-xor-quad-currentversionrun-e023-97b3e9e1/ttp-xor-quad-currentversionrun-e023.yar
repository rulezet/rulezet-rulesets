rule TTP_XOR_QUAD_CurrentVersionRun_e023 {
  strings:
    $key_e023 = { b3 4c [2] 97 42 [2] bc 6e [2] 92 4c [2] 86 57 [2] 89 4d [2] 97 50 [2] 95 51 [2] 8e 57 [2] 92 50 [2] 8e 7f }

  condition:
    any of them
}