rule TTP_XOR_QUAD_CurrentVersionRun_c8ba {
  strings:
    $key_c8ba = { 9b d5 [2] bf db [2] 94 f7 [2] ba d5 [2] ae ce [2] a1 d4 [2] bf c9 [2] bd c8 [2] a6 ce [2] ba c9 [2] a6 e6 }

  condition:
    any of them
}