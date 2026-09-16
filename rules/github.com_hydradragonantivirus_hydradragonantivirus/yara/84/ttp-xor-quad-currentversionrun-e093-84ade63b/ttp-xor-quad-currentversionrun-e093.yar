rule TTP_XOR_QUAD_CurrentVersionRun_e093 {
  strings:
    $key_e093 = { b3 fc [2] 97 f2 [2] bc de [2] 92 fc [2] 86 e7 [2] 89 fd [2] 97 e0 [2] 95 e1 [2] 8e e7 [2] 92 e0 [2] 8e cf }

  condition:
    any of them
}