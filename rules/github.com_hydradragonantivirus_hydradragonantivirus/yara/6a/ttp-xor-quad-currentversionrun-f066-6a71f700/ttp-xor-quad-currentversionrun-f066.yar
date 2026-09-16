rule TTP_XOR_QUAD_CurrentVersionRun_f066 {
  strings:
    $key_f066 = { a3 09 [2] 87 07 [2] ac 2b [2] 82 09 [2] 96 12 [2] 99 08 [2] 87 15 [2] 85 14 [2] 9e 12 [2] 82 15 [2] 9e 3a }

  condition:
    any of them
}