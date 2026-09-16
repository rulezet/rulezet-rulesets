rule TTP_XOR_QUAD_CurrentVersionRun_f55c {
  strings:
    $key_f55c = { a6 33 [2] 82 3d [2] a9 11 [2] 87 33 [2] 93 28 [2] 9c 32 [2] 82 2f [2] 80 2e [2] 9b 28 [2] 87 2f [2] 9b 00 }

  condition:
    any of them
}