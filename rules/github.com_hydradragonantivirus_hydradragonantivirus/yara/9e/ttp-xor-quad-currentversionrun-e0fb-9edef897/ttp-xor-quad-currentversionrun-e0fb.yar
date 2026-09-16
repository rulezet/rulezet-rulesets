rule TTP_XOR_QUAD_CurrentVersionRun_e0fb {
  strings:
    $key_e0fb = { b3 94 [2] 97 9a [2] bc b6 [2] 92 94 [2] 86 8f [2] 89 95 [2] 97 88 [2] 95 89 [2] 8e 8f [2] 92 88 [2] 8e a7 }

  condition:
    any of them
}