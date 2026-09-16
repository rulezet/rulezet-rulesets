rule TTP_XOR_QUAD_CurrentVersionRun_e032 {
  strings:
    $key_e032 = { b3 5d [2] 97 53 [2] bc 7f [2] 92 5d [2] 86 46 [2] 89 5c [2] 97 41 [2] 95 40 [2] 8e 46 [2] 92 41 [2] 8e 6e }

  condition:
    any of them
}