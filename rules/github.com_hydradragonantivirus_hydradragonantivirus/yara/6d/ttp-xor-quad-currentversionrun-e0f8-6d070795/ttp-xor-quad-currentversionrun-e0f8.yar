rule TTP_XOR_QUAD_CurrentVersionRun_e0f8 {
  strings:
    $key_e0f8 = { b3 97 [2] 97 99 [2] bc b5 [2] 92 97 [2] 86 8c [2] 89 96 [2] 97 8b [2] 95 8a [2] 8e 8c [2] 92 8b [2] 8e a4 }

  condition:
    any of them
}