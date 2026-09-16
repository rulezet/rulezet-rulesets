rule TTP_XOR_QUAD_CurrentVersionRun_f21c {
  strings:
    $key_f21c = { a1 73 [2] 85 7d [2] ae 51 [2] 80 73 [2] 94 68 [2] 9b 72 [2] 85 6f [2] 87 6e [2] 9c 68 [2] 80 6f [2] 9c 40 }

  condition:
    any of them
}