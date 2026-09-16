rule TTP_XOR_QUAD_CurrentVersionRun_f04a {
  strings:
    $key_f04a = { a3 25 [2] 87 2b [2] ac 07 [2] 82 25 [2] 96 3e [2] 99 24 [2] 87 39 [2] 85 38 [2] 9e 3e [2] 82 39 [2] 9e 16 }

  condition:
    any of them
}