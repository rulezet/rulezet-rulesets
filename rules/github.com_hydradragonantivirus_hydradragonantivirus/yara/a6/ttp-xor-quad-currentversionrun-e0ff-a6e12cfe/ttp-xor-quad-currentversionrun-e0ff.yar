rule TTP_XOR_QUAD_CurrentVersionRun_e0ff {
  strings:
    $key_e0ff = { b3 90 [2] 97 9e [2] bc b2 [2] 92 90 [2] 86 8b [2] 89 91 [2] 97 8c [2] 95 8d [2] 8e 8b [2] 92 8c [2] 8e a3 }

  condition:
    any of them
}