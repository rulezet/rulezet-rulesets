rule TTP_XOR_QUAD_CurrentVersionRun_e066 {
  strings:
    $key_e066 = { b3 09 [2] 97 07 [2] bc 2b [2] 92 09 [2] 86 12 [2] 89 08 [2] 97 15 [2] 95 14 [2] 8e 12 [2] 92 15 [2] 8e 3a }

  condition:
    any of them
}