rule TTP_XOR_QUAD_CurrentVersionRun_f06d {
  strings:
    $key_f06d = { a3 02 [2] 87 0c [2] ac 20 [2] 82 02 [2] 96 19 [2] 99 03 [2] 87 1e [2] 85 1f [2] 9e 19 [2] 82 1e [2] 9e 31 }

  condition:
    any of them
}