rule TTP_XOR_QUAD_CurrentVersionRun_f90e {
  strings:
    $key_f90e = { aa 61 [2] 8e 6f [2] a5 43 [2] 8b 61 [2] 9f 7a [2] 90 60 [2] 8e 7d [2] 8c 7c [2] 97 7a [2] 8b 7d [2] 97 52 }

  condition:
    any of them
}