rule TTP_XOR_QUAD_CurrentVersionRun_e002 {
  strings:
    $key_e002 = { b3 6d [2] 97 63 [2] bc 4f [2] 92 6d [2] 86 76 [2] 89 6c [2] 97 71 [2] 95 70 [2] 8e 76 [2] 92 71 [2] 8e 5e }

  condition:
    any of them
}