rule TTP_XOR_QUAD_CurrentVersionRun_e371 {
  strings:
    $key_e371 = { b0 1e [2] 94 10 [2] bf 3c [2] 91 1e [2] 85 05 [2] 8a 1f [2] 94 02 [2] 96 03 [2] 8d 05 [2] 91 02 [2] 8d 2d }

  condition:
    any of them
}