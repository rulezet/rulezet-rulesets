rule TTP_XOR_QUAD_CurrentVersionRun_e02d {
  strings:
    $key_e02d = { b3 42 [2] 97 4c [2] bc 60 [2] 92 42 [2] 86 59 [2] 89 43 [2] 97 5e [2] 95 5f [2] 8e 59 [2] 92 5e [2] 8e 71 }

  condition:
    any of them
}