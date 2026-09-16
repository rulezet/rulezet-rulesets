rule TTP_XOR_QUAD_CurrentVersionRun_3d60 {
  strings:
    $key_3d60 = { 6e 0f [2] 4a 01 [2] 61 2d [2] 4f 0f [2] 5b 14 [2] 54 0e [2] 4a 13 [2] 48 12 [2] 53 14 [2] 4f 13 [2] 53 3c }

  condition:
    any of them
}