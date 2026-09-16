rule TTP_XOR_QUAD_CurrentVersionRun_e016 {
  strings:
    $key_e016 = { b3 79 [2] 97 77 [2] bc 5b [2] 92 79 [2] 86 62 [2] 89 78 [2] 97 65 [2] 95 64 [2] 8e 62 [2] 92 65 [2] 8e 4a }

  condition:
    any of them
}