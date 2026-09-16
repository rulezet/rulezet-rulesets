rule TTP_XOR_QUAD_CurrentVersionRun_f026 {
  strings:
    $key_f026 = { a3 49 [2] 87 47 [2] ac 6b [2] 82 49 [2] 96 52 [2] 99 48 [2] 87 55 [2] 85 54 [2] 9e 52 [2] 82 55 [2] 9e 7a }

  condition:
    any of them
}