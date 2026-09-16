rule TTP_XOR_QUAD_CurrentVersionRun_e005 {
  strings:
    $key_e005 = { b3 6a [2] 97 64 [2] bc 48 [2] 92 6a [2] 86 71 [2] 89 6b [2] 97 76 [2] 95 77 [2] 8e 71 [2] 92 76 [2] 8e 59 }

  condition:
    any of them
}