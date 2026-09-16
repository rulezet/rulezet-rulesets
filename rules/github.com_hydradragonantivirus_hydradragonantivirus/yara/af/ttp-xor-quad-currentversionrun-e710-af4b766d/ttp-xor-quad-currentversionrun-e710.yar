rule TTP_XOR_QUAD_CurrentVersionRun_e710 {
  strings:
    $key_e710 = { b4 7f [2] 90 71 [2] bb 5d [2] 95 7f [2] 81 64 [2] 8e 7e [2] 90 63 [2] 92 62 [2] 89 64 [2] 95 63 [2] 89 4c }

  condition:
    any of them
}