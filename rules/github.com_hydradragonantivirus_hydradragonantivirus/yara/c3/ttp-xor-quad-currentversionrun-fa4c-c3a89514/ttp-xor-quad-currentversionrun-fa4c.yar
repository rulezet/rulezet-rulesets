rule TTP_XOR_QUAD_CurrentVersionRun_fa4c {
  strings:
    $key_fa4c = { a9 23 [2] 8d 2d [2] a6 01 [2] 88 23 [2] 9c 38 [2] 93 22 [2] 8d 3f [2] 8f 3e [2] 94 38 [2] 88 3f [2] 94 10 }

  condition:
    any of them
}