rule TTP_XOR_QUAD_CurrentVersionRun_6100 {
  strings:
    $key_6100 = { 32 6f [2] 16 61 [2] 3d 4d [2] 13 6f [2] 07 74 [2] 08 6e [2] 16 73 [2] 14 72 [2] 0f 74 [2] 13 73 [2] 0f 5c }

  condition:
    any of them
}