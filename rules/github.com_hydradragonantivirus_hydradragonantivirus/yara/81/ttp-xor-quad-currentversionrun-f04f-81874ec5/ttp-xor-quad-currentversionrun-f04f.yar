rule TTP_XOR_QUAD_CurrentVersionRun_f04f {
  strings:
    $key_f04f = { a3 20 [2] 87 2e [2] ac 02 [2] 82 20 [2] 96 3b [2] 99 21 [2] 87 3c [2] 85 3d [2] 9e 3b [2] 82 3c [2] 9e 13 }

  condition:
    any of them
}