rule TTP_XOR_QUAD_CurrentVersionRun_e021 {
  strings:
    $key_e021 = { b3 4e [2] 97 40 [2] bc 6c [2] 92 4e [2] 86 55 [2] 89 4f [2] 97 52 [2] 95 53 [2] 8e 55 [2] 92 52 [2] 8e 7d }

  condition:
    any of them
}