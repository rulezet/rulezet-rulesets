rule TTP_XOR_QUAD_CurrentVersionRun_e36c {
  strings:
    $key_e36c = { b0 03 [2] 94 0d [2] bf 21 [2] 91 03 [2] 85 18 [2] 8a 02 [2] 94 1f [2] 96 1e [2] 8d 18 [2] 91 1f [2] 8d 30 }

  condition:
    any of them
}