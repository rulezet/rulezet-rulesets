rule TTP_XOR_QUAD_CurrentVersionRun_f480 {
  strings:
    $key_f480 = { a7 ef [2] 83 e1 [2] a8 cd [2] 86 ef [2] 92 f4 [2] 9d ee [2] 83 f3 [2] 81 f2 [2] 9a f4 [2] 86 f3 [2] 9a dc }

  condition:
    any of them
}