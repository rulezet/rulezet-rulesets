rule TTP_XOR_QUAD_CurrentVersionRun_e0fa {
  strings:
    $key_e0fa = { b3 95 [2] 97 9b [2] bc b7 [2] 92 95 [2] 86 8e [2] 89 94 [2] 97 89 [2] 95 88 [2] 8e 8e [2] 92 89 [2] 8e a6 }

  condition:
    any of them
}