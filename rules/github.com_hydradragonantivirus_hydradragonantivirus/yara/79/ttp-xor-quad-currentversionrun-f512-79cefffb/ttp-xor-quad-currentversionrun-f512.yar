rule TTP_XOR_QUAD_CurrentVersionRun_f512 {
  strings:
    $key_f512 = { a6 7d [2] 82 73 [2] a9 5f [2] 87 7d [2] 93 66 [2] 9c 7c [2] 82 61 [2] 80 60 [2] 9b 66 [2] 87 61 [2] 9b 4e }

  condition:
    any of them
}