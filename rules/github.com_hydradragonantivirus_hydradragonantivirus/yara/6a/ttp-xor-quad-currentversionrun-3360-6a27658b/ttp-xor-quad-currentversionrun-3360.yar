rule TTP_XOR_QUAD_CurrentVersionRun_3360 {
  strings:
    $key_3360 = { 60 0f [2] 44 01 [2] 6f 2d [2] 41 0f [2] 55 14 [2] 5a 0e [2] 44 13 [2] 46 12 [2] 5d 14 [2] 41 13 [2] 5d 3c }

  condition:
    any of them
}