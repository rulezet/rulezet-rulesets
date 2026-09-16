rule TTP_XOR_QUAD_CurrentVersionRun_fa20 {
  strings:
    $key_fa20 = { a9 4f [2] 8d 41 [2] a6 6d [2] 88 4f [2] 9c 54 [2] 93 4e [2] 8d 53 [2] 8f 52 [2] 94 54 [2] 88 53 [2] 94 7c }

  condition:
    any of them
}