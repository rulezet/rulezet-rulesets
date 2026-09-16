rule TTP_XOR_QUAD_CurrentVersionRun_e031 {
  strings:
    $key_e031 = { b3 5e [2] 97 50 [2] bc 7c [2] 92 5e [2] 86 45 [2] 89 5f [2] 97 42 [2] 95 43 [2] 8e 45 [2] 92 42 [2] 8e 6d }

  condition:
    any of them
}