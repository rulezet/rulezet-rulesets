rule TTP_XOR_QUAD_CurrentVersionRun_e0a2 {
  strings:
    $key_e0a2 = { b3 cd [2] 97 c3 [2] bc ef [2] 92 cd [2] 86 d6 [2] 89 cc [2] 97 d1 [2] 95 d0 [2] 8e d6 [2] 92 d1 [2] 8e fe }

  condition:
    any of them
}