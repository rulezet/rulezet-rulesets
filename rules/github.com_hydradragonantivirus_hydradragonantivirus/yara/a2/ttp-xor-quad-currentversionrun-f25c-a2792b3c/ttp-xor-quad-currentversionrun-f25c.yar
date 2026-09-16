rule TTP_XOR_QUAD_CurrentVersionRun_f25c {
  strings:
    $key_f25c = { a1 33 [2] 85 3d [2] ae 11 [2] 80 33 [2] 94 28 [2] 9b 32 [2] 85 2f [2] 87 2e [2] 9c 28 [2] 80 2f [2] 9c 00 }

  condition:
    any of them
}