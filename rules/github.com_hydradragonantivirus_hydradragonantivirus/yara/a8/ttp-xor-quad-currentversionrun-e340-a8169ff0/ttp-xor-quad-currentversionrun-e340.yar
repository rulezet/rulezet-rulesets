rule TTP_XOR_QUAD_CurrentVersionRun_e340 {
  strings:
    $key_e340 = { b0 2f [2] 94 21 [2] bf 0d [2] 91 2f [2] 85 34 [2] 8a 2e [2] 94 33 [2] 96 32 [2] 8d 34 [2] 91 33 [2] 8d 1c }

  condition:
    any of them
}