rule TTP_XOR_QUAD_CurrentVersionRun_f850 {
  strings:
    $key_f850 = { ab 3f [2] 8f 31 [2] a4 1d [2] 8a 3f [2] 9e 24 [2] 91 3e [2] 8f 23 [2] 8d 22 [2] 96 24 [2] 8a 23 [2] 96 0c }

  condition:
    any of them
}