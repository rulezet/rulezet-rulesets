rule TTP_XOR_QUAD_CurrentVersionRun_e022 {
  strings:
    $key_e022 = { b3 4d [2] 97 43 [2] bc 6f [2] 92 4d [2] 86 56 [2] 89 4c [2] 97 51 [2] 95 50 [2] 8e 56 [2] 92 51 [2] 8e 7e }

  condition:
    any of them
}