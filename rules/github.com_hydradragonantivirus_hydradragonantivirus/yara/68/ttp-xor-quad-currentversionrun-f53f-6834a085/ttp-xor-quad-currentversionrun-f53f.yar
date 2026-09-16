rule TTP_XOR_QUAD_CurrentVersionRun_f53f {
  strings:
    $key_f53f = { a6 50 [2] 82 5e [2] a9 72 [2] 87 50 [2] 93 4b [2] 9c 51 [2] 82 4c [2] 80 4d [2] 9b 4b [2] 87 4c [2] 9b 63 }

  condition:
    any of them
}