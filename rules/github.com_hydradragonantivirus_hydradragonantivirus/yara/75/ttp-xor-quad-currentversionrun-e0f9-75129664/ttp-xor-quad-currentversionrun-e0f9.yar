rule TTP_XOR_QUAD_CurrentVersionRun_e0f9 {
  strings:
    $key_e0f9 = { b3 96 [2] 97 98 [2] bc b4 [2] 92 96 [2] 86 8d [2] 89 97 [2] 97 8a [2] 95 8b [2] 8e 8d [2] 92 8a [2] 8e a5 }

  condition:
    any of them
}