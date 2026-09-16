rule TTP_XOR_QUAD_CurrentVersionRun_3f60 {
  strings:
    $key_3f60 = { 6c 0f [2] 48 01 [2] 63 2d [2] 4d 0f [2] 59 14 [2] 56 0e [2] 48 13 [2] 4a 12 [2] 51 14 [2] 4d 13 [2] 51 3c }

  condition:
    any of them
}