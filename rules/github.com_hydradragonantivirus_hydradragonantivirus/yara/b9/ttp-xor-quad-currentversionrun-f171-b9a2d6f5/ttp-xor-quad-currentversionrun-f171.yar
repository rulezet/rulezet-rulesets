rule TTP_XOR_QUAD_CurrentVersionRun_f171 {
  strings:
    $key_f171 = { a2 1e [2] 86 10 [2] ad 3c [2] 83 1e [2] 97 05 [2] 98 1f [2] 86 02 [2] 84 03 [2] 9f 05 [2] 83 02 [2] 9f 2d }

  condition:
    any of them
}