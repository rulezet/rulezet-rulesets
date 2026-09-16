rule TTP_XOR_QUAD_CurrentVersionRun_4f00 {
  strings:
    $key_4f00 = { 1c 6f [2] 38 61 [2] 13 4d [2] 3d 6f [2] 29 74 [2] 26 6e [2] 38 73 [2] 3a 72 [2] 21 74 [2] 3d 73 [2] 21 5c }

  condition:
    any of them
}