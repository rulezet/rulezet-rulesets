rule TTP_XOR_QUAD_CurrentVersionRun_f580 {
  strings:
    $key_f580 = { a6 ef [2] 82 e1 [2] a9 cd [2] 87 ef [2] 93 f4 [2] 9c ee [2] 82 f3 [2] 80 f2 [2] 9b f4 [2] 87 f3 [2] 9b dc }

  condition:
    any of them
}