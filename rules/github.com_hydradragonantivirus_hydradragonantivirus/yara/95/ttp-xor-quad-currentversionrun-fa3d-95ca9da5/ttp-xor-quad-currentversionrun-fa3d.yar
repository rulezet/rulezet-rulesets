rule TTP_XOR_QUAD_CurrentVersionRun_fa3d {
  strings:
    $key_fa3d = { a9 52 [2] 8d 5c [2] a6 70 [2] 88 52 [2] 9c 49 [2] 93 53 [2] 8d 4e [2] 8f 4f [2] 94 49 [2] 88 4e [2] 94 61 }

  condition:
    any of them
}