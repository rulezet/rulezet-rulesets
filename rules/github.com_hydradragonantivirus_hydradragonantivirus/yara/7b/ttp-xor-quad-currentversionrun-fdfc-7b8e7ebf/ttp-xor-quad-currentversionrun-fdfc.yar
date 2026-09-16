rule TTP_XOR_QUAD_CurrentVersionRun_fdfc {
  strings:
    $key_fdfc = { ae 93 [2] 8a 9d [2] a1 b1 [2] 8f 93 [2] 9b 88 [2] 94 92 [2] 8a 8f [2] 88 8e [2] 93 88 [2] 8f 8f [2] 93 a0 }

  condition:
    any of them
}