rule TTP_XOR_QUAD_CurrentVersionRun_f012 {
  strings:
    $key_f012 = { a3 7d [2] 87 73 [2] ac 5f [2] 82 7d [2] 96 66 [2] 99 7c [2] 87 61 [2] 85 60 [2] 9e 66 [2] 82 61 [2] 9e 4e }

  condition:
    any of them
}