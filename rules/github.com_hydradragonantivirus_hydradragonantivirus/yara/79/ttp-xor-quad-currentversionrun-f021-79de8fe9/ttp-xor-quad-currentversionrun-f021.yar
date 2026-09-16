rule TTP_XOR_QUAD_CurrentVersionRun_f021 {
  strings:
    $key_f021 = { a3 4e [2] 87 40 [2] ac 6c [2] 82 4e [2] 96 55 [2] 99 4f [2] 87 52 [2] 85 53 [2] 9e 55 [2] 82 52 [2] 9e 7d }

  condition:
    any of them
}