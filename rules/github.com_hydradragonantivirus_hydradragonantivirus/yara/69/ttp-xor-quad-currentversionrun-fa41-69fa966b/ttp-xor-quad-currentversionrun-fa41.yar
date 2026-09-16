rule TTP_XOR_QUAD_CurrentVersionRun_fa41 {
  strings:
    $key_fa41 = { a9 2e [2] 8d 20 [2] a6 0c [2] 88 2e [2] 9c 35 [2] 93 2f [2] 8d 32 [2] 8f 33 [2] 94 35 [2] 88 32 [2] 94 1d }

  condition:
    any of them
}