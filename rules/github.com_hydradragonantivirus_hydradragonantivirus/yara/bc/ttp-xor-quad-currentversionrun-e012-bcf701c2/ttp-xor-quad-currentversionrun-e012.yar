rule TTP_XOR_QUAD_CurrentVersionRun_e012 {
  strings:
    $key_e012 = { b3 7d [2] 97 73 [2] bc 5f [2] 92 7d [2] 86 66 [2] 89 7c [2] 97 61 [2] 95 60 [2] 8e 66 [2] 92 61 [2] 8e 4e }

  condition:
    any of them
}