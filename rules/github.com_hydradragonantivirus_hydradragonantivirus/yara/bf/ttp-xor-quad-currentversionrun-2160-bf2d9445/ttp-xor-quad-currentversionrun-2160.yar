rule TTP_XOR_QUAD_CurrentVersionRun_2160 {
  strings:
    $key_2160 = { 72 0f [2] 56 01 [2] 7d 2d [2] 53 0f [2] 47 14 [2] 48 0e [2] 56 13 [2] 54 12 [2] 4f 14 [2] 53 13 [2] 4f 3c }

  condition:
    any of them
}