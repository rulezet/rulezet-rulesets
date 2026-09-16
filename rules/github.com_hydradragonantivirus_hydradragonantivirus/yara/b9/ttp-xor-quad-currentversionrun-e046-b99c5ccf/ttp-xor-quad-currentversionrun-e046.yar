rule TTP_XOR_QUAD_CurrentVersionRun_e046 {
  strings:
    $key_e046 = { b3 29 [2] 97 27 [2] bc 0b [2] 92 29 [2] 86 32 [2] 89 28 [2] 97 35 [2] 95 34 [2] 8e 32 [2] 92 35 [2] 8e 1a }

  condition:
    any of them
}