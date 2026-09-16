rule TTP_XOR_QUAD_CurrentVersionRun_e0e9 {
  strings:
    $key_e0e9 = { b3 86 [2] 97 88 [2] bc a4 [2] 92 86 [2] 86 9d [2] 89 87 [2] 97 9a [2] 95 9b [2] 8e 9d [2] 92 9a [2] 8e b5 }

  condition:
    any of them
}