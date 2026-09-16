rule TTP_XOR_QUAD_CurrentVersionRun_f259 {
  strings:
    $key_f259 = { a1 36 [2] 85 38 [2] ae 14 [2] 80 36 [2] 94 2d [2] 9b 37 [2] 85 2a [2] 87 2b [2] 9c 2d [2] 80 2a [2] 9c 05 }

  condition:
    any of them
}