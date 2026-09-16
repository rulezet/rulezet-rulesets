rule TTP_XOR_QUAD_CurrentVersionRun_fafc {
  strings:
    $key_fafc = { a9 93 [2] 8d 9d [2] a6 b1 [2] 88 93 [2] 9c 88 [2] 93 92 [2] 8d 8f [2] 8f 8e [2] 94 88 [2] 88 8f [2] 94 a0 }

  condition:
    any of them
}