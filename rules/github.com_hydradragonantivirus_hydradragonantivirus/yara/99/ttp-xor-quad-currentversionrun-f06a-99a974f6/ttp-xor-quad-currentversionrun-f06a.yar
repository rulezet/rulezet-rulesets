rule TTP_XOR_QUAD_CurrentVersionRun_f06a {
  strings:
    $key_f06a = { a3 05 [2] 87 0b [2] ac 27 [2] 82 05 [2] 96 1e [2] 99 04 [2] 87 19 [2] 85 18 [2] 9e 1e [2] 82 19 [2] 9e 36 }

  condition:
    any of them
}