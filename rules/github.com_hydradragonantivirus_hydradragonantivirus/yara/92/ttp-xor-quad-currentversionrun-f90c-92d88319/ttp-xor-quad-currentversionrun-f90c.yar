rule TTP_XOR_QUAD_CurrentVersionRun_f90c {
  strings:
    $key_f90c = { aa 63 [2] 8e 6d [2] a5 41 [2] 8b 63 [2] 9f 78 [2] 90 62 [2] 8e 7f [2] 8c 7e [2] 97 78 [2] 8b 7f [2] 97 50 }

  condition:
    any of them
}