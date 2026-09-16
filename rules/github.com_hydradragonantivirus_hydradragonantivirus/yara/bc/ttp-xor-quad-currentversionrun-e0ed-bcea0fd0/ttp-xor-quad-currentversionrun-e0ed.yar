rule TTP_XOR_QUAD_CurrentVersionRun_e0ed {
  strings:
    $key_e0ed = { b3 82 [2] 97 8c [2] bc a0 [2] 92 82 [2] 86 99 [2] 89 83 [2] 97 9e [2] 95 9f [2] 8e 99 [2] 92 9e [2] 8e b1 }

  condition:
    any of them
}