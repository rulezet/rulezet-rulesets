rule TTP_XOR_QUAD_CurrentVersionRun_f00a {
  strings:
    $key_f00a = { a3 65 [2] 87 6b [2] ac 47 [2] 82 65 [2] 96 7e [2] 99 64 [2] 87 79 [2] 85 78 [2] 9e 7e [2] 82 79 [2] 9e 56 }

  condition:
    any of them
}