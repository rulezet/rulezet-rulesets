rule TTP_XOR_QUAD_CurrentVersionRun_fa12 {
  strings:
    $key_fa12 = { a9 7d [2] 8d 73 [2] a6 5f [2] 88 7d [2] 9c 66 [2] 93 7c [2] 8d 61 [2] 8f 60 [2] 94 66 [2] 88 61 [2] 94 4e }

  condition:
    any of them
}