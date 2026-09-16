rule TTP_XOR_QUAD_CurrentVersionRun_fafd {
  strings:
    $key_fafd = { a9 92 [2] 8d 9c [2] a6 b0 [2] 88 92 [2] 9c 89 [2] 93 93 [2] 8d 8e [2] 8f 8f [2] 94 89 [2] 88 8e [2] 94 a1 }

  condition:
    any of them
}