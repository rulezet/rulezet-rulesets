rule TTP_XOR_QUAD_CurrentVersionRun_f24c {
  strings:
    $key_f24c = { a1 23 [2] 85 2d [2] ae 01 [2] 80 23 [2] 94 38 [2] 9b 22 [2] 85 3f [2] 87 3e [2] 9c 38 [2] 80 3f [2] 9c 10 }

  condition:
    any of them
}