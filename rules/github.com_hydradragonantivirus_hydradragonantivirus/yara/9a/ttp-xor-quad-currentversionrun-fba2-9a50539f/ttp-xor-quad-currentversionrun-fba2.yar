rule TTP_XOR_QUAD_CurrentVersionRun_fba2 {
  strings:
    $key_fba2 = { a8 cd [2] 8c c3 [2] a7 ef [2] 89 cd [2] 9d d6 [2] 92 cc [2] 8c d1 [2] 8e d0 [2] 95 d6 [2] 89 d1 [2] 95 fe }

  condition:
    any of them
}