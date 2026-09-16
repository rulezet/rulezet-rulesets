rule TTP_XOR_QUAD_CurrentVersionRun_e052 {
  strings:
    $key_e052 = { b3 3d [2] 97 33 [2] bc 1f [2] 92 3d [2] 86 26 [2] 89 3c [2] 97 21 [2] 95 20 [2] 8e 26 [2] 92 21 [2] 8e 0e }

  condition:
    any of them
}