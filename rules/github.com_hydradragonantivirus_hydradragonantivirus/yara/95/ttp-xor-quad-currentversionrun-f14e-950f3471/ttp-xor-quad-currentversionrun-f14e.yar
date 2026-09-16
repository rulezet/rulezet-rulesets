rule TTP_XOR_QUAD_CurrentVersionRun_f14e {
  strings:
    $key_f14e = { a2 21 [2] 86 2f [2] ad 03 [2] 83 21 [2] 97 3a [2] 98 20 [2] 86 3d [2] 84 3c [2] 9f 3a [2] 83 3d [2] 9f 12 }

  condition:
    any of them
}