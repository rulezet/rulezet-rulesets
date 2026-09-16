rule TTP_XOR_QUAD_CurrentVersionRun_b090 {
  strings:
    $key_b090 = { e3 ff [2] c7 f1 [2] ec dd [2] c2 ff [2] d6 e4 [2] d9 fe [2] c7 e3 [2] c5 e2 [2] de e4 [2] c2 e3 [2] de cc }

  condition:
    any of them
}