rule TTP_XOR_QUAD_CurrentVersionRun_e372 {
  strings:
    $key_e372 = { b0 1d [2] 94 13 [2] bf 3f [2] 91 1d [2] 85 06 [2] 8a 1c [2] 94 01 [2] 96 00 [2] 8d 06 [2] 91 01 [2] 8d 2e }

  condition:
    any of them
}