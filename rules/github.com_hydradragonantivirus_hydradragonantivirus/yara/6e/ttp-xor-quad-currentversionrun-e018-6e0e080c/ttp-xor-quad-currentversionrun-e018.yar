rule TTP_XOR_QUAD_CurrentVersionRun_e018 {
  strings:
    $key_e018 = { b3 77 [2] 97 79 [2] bc 55 [2] 92 77 [2] 86 6c [2] 89 76 [2] 97 6b [2] 95 6a [2] 8e 6c [2] 92 6b [2] 8e 44 }

  condition:
    any of them
}