rule TTP_XOR_QUAD_CurrentVersionRun_e00e {
  strings:
    $key_e00e = { b3 61 [2] 97 6f [2] bc 43 [2] 92 61 [2] 86 7a [2] 89 60 [2] 97 7d [2] 95 7c [2] 8e 7a [2] 92 7d [2] 8e 52 }

  condition:
    any of them
}