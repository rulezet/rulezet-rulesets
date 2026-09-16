rule TTP_XOR_QUAD_CurrentVersionRun_f53d {
  strings:
    $key_f53d = { a6 52 [2] 82 5c [2] a9 70 [2] 87 52 [2] 93 49 [2] 9c 53 [2] 82 4e [2] 80 4f [2] 9b 49 [2] 87 4e [2] 9b 61 }

  condition:
    any of them
}