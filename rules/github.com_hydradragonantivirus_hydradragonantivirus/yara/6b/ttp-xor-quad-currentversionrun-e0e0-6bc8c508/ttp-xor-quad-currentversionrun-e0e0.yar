rule TTP_XOR_QUAD_CurrentVersionRun_e0e0 {
  strings:
    $key_e0e0 = { b3 8f [2] 97 81 [2] bc ad [2] 92 8f [2] 86 94 [2] 89 8e [2] 97 93 [2] 95 92 [2] 8e 94 [2] 92 93 [2] 8e bc }

  condition:
    any of them
}