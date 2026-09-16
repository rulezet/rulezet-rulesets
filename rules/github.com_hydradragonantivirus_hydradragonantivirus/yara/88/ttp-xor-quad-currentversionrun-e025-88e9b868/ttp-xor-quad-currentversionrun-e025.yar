rule TTP_XOR_QUAD_CurrentVersionRun_e025 {
  strings:
    $key_e025 = { b3 4a [2] 97 44 [2] bc 68 [2] 92 4a [2] 86 51 [2] 89 4b [2] 97 56 [2] 95 57 [2] 8e 51 [2] 92 56 [2] 8e 79 }

  condition:
    any of them
}