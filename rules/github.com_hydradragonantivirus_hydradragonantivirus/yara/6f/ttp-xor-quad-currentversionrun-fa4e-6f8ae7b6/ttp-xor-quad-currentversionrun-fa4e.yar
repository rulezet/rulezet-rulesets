rule TTP_XOR_QUAD_CurrentVersionRun_fa4e {
  strings:
    $key_fa4e = { a9 21 [2] 8d 2f [2] a6 03 [2] 88 21 [2] 9c 3a [2] 93 20 [2] 8d 3d [2] 8f 3c [2] 94 3a [2] 88 3d [2] 94 12 }

  condition:
    any of them
}