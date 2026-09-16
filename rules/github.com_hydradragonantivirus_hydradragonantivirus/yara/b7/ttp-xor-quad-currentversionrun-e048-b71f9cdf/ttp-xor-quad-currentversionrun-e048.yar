rule TTP_XOR_QUAD_CurrentVersionRun_e048 {
  strings:
    $key_e048 = { b3 27 [2] 97 29 [2] bc 05 [2] 92 27 [2] 86 3c [2] 89 26 [2] 97 3b [2] 95 3a [2] 8e 3c [2] 92 3b [2] 8e 14 }

  condition:
    any of them
}