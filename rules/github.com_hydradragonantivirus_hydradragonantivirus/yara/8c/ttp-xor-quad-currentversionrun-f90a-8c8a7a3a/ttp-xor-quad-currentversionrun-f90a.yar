rule TTP_XOR_QUAD_CurrentVersionRun_f90a {
  strings:
    $key_f90a = { aa 65 [2] 8e 6b [2] a5 47 [2] 8b 65 [2] 9f 7e [2] 90 64 [2] 8e 79 [2] 8c 78 [2] 97 7e [2] 8b 79 [2] 97 56 }

  condition:
    any of them
}