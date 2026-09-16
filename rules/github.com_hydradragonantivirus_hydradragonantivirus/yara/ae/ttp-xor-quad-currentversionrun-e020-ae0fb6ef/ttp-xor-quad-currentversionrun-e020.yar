rule TTP_XOR_QUAD_CurrentVersionRun_e020 {
  strings:
    $key_e020 = { b3 4f [2] 97 41 [2] bc 6d [2] 92 4f [2] 86 54 [2] 89 4e [2] 97 53 [2] 95 52 [2] 8e 54 [2] 92 53 [2] 8e 7c }

  condition:
    any of them
}