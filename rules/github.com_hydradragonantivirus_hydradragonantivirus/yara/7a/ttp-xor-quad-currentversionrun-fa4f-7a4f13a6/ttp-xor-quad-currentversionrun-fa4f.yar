rule TTP_XOR_QUAD_CurrentVersionRun_fa4f {
  strings:
    $key_fa4f = { a9 20 [2] 8d 2e [2] a6 02 [2] 88 20 [2] 9c 3b [2] 93 21 [2] 8d 3c [2] 8f 3d [2] 94 3b [2] 88 3c [2] 94 13 }

  condition:
    any of them
}