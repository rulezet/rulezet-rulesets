rule TTP_XOR_QUAD_CurrentVersionRun_e076 {
  strings:
    $key_e076 = { b3 19 [2] 97 17 [2] bc 3b [2] 92 19 [2] 86 02 [2] 89 18 [2] 97 05 [2] 95 04 [2] 8e 02 [2] 92 05 [2] 8e 2a }

  condition:
    any of them
}