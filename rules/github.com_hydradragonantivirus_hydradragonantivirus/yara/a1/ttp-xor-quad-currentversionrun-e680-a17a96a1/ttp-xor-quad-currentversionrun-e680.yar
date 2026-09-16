rule TTP_XOR_QUAD_CurrentVersionRun_e680 {
  strings:
    $key_e680 = { b5 ef [2] 91 e1 [2] ba cd [2] 94 ef [2] 80 f4 [2] 8f ee [2] 91 f3 [2] 93 f2 [2] 88 f4 [2] 94 f3 [2] 88 dc }

  condition:
    any of them
}