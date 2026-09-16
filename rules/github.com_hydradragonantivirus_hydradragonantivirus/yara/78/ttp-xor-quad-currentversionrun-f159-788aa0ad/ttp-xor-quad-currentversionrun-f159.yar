rule TTP_XOR_QUAD_CurrentVersionRun_f159 {
  strings:
    $key_f159 = { a2 36 [2] 86 38 [2] ad 14 [2] 83 36 [2] 97 2d [2] 98 37 [2] 86 2a [2] 84 2b [2] 9f 2d [2] 83 2a [2] 9f 05 }

  condition:
    any of them
}