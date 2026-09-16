rule TTP_XOR_QUAD_CurrentVersionRun_e0e8 {
  strings:
    $key_e0e8 = { b3 87 [2] 97 89 [2] bc a5 [2] 92 87 [2] 86 9c [2] 89 86 [2] 97 9b [2] 95 9a [2] 8e 9c [2] 92 9b [2] 8e b4 }

  condition:
    any of them
}