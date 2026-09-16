rule TTP_XOR_QUAD_CurrentVersionRun_f75c {
  strings:
    $key_f75c = { a4 33 [2] 80 3d [2] ab 11 [2] 85 33 [2] 91 28 [2] 9e 32 [2] 80 2f [2] 82 2e [2] 99 28 [2] 85 2f [2] 99 00 }

  condition:
    any of them
}