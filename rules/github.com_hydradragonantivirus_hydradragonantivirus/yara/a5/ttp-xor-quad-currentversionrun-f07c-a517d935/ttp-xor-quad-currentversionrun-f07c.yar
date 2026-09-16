rule TTP_XOR_QUAD_CurrentVersionRun_f07c {
  strings:
    $key_f07c = { a3 13 [2] 87 1d [2] ac 31 [2] 82 13 [2] 96 08 [2] 99 12 [2] 87 0f [2] 85 0e [2] 9e 08 [2] 82 0f [2] 9e 20 }

  condition:
    any of them
}