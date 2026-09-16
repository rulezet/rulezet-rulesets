rule TTP_XOR_QUAD_CurrentVersionRun_1320 {
  strings:
    $key_1320 = { 40 4f [2] 64 41 [2] 4f 6d [2] 61 4f [2] 75 54 [2] 7a 4e [2] 64 53 [2] 66 52 [2] 7d 54 [2] 61 53 [2] 7d 7c }

  condition:
    any of them
}