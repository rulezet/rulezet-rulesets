rule TTP_XOR_QUAD_CurrentVersionRun_f04e {
  strings:
    $key_f04e = { a3 21 [2] 87 2f [2] ac 03 [2] 82 21 [2] 96 3a [2] 99 20 [2] 87 3d [2] 85 3c [2] 9e 3a [2] 82 3d [2] 9e 12 }

  condition:
    any of them
}