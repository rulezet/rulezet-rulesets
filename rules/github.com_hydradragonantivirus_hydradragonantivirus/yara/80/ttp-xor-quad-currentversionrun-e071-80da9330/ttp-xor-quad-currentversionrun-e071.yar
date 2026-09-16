rule TTP_XOR_QUAD_CurrentVersionRun_e071 {
  strings:
    $key_e071 = { b3 1e [2] 97 10 [2] bc 3c [2] 92 1e [2] 86 05 [2] 89 1f [2] 97 02 [2] 95 03 [2] 8e 05 [2] 92 02 [2] 8e 2d }

  condition:
    any of them
}