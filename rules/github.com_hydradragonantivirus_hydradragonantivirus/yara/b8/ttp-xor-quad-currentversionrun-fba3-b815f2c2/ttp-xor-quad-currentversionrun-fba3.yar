rule TTP_XOR_QUAD_CurrentVersionRun_fba3 {
  strings:
    $key_fba3 = { a8 cc [2] 8c c2 [2] a7 ee [2] 89 cc [2] 9d d7 [2] 92 cd [2] 8c d0 [2] 8e d1 [2] 95 d7 [2] 89 d0 [2] 95 ff }

  condition:
    any of them
}