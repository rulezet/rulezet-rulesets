rule TTP_XOR_QUAD_CurrentVersionRun_e033 {
  strings:
    $key_e033 = { b3 5c [2] 97 52 [2] bc 7e [2] 92 5c [2] 86 47 [2] 89 5d [2] 97 40 [2] 95 41 [2] 8e 47 [2] 92 40 [2] 8e 6f }

  condition:
    any of them
}