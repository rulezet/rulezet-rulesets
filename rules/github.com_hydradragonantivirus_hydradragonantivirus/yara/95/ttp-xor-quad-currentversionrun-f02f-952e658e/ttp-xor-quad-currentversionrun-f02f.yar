rule TTP_XOR_QUAD_CurrentVersionRun_f02f {
  strings:
    $key_f02f = { a3 40 [2] 87 4e [2] ac 62 [2] 82 40 [2] 96 5b [2] 99 41 [2] 87 5c [2] 85 5d [2] 9e 5b [2] 82 5c [2] 9e 73 }

  condition:
    any of them
}