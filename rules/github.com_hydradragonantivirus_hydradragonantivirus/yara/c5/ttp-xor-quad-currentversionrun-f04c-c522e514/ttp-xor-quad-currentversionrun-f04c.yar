rule TTP_XOR_QUAD_CurrentVersionRun_f04c {
  strings:
    $key_f04c = { a3 23 [2] 87 2d [2] ac 01 [2] 82 23 [2] 96 38 [2] 99 22 [2] 87 3f [2] 85 3e [2] 9e 38 [2] 82 3f [2] 9e 10 }

  condition:
    any of them
}