rule TTP_XOR_QUAD_CurrentVersionRun_faa2 {
  strings:
    $key_faa2 = { a9 cd [2] 8d c3 [2] a6 ef [2] 88 cd [2] 9c d6 [2] 93 cc [2] 8d d1 [2] 8f d0 [2] 94 d6 [2] 88 d1 [2] 94 fe }

  condition:
    any of them
}