rule TTP_XOR_QUAD_CurrentVersionRun_e860 {
  strings:
    $key_e860 = { bb 0f [2] 9f 01 [2] b4 2d [2] 9a 0f [2] 8e 14 [2] 81 0e [2] 9f 13 [2] 9d 12 [2] 86 14 [2] 9a 13 [2] 86 3c }

  condition:
    any of them
}