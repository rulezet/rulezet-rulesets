rule TTP_XOR_QUAD_CurrentVersionRun_f01f {
  strings:
    $key_f01f = { a3 70 [2] 87 7e [2] ac 52 [2] 82 70 [2] 96 6b [2] 99 71 [2] 87 6c [2] 85 6d [2] 9e 6b [2] 82 6c [2] 9e 43 }

  condition:
    any of them
}