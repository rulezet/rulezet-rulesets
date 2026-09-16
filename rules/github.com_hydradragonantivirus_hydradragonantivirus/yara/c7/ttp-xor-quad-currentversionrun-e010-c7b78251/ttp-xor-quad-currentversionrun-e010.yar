rule TTP_XOR_QUAD_CurrentVersionRun_e010 {
  strings:
    $key_e010 = { b3 7f [2] 97 71 [2] bc 5d [2] 92 7f [2] 86 64 [2] 89 7e [2] 97 63 [2] 95 62 [2] 8e 64 [2] 92 63 [2] 8e 4c }

  condition:
    any of them
}