rule TTP_XOR_QUAD_CurrentVersionRun_4b60 {
  strings:
    $key_4b60 = { 18 0f [2] 3c 01 [2] 17 2d [2] 39 0f [2] 2d 14 [2] 22 0e [2] 3c 13 [2] 3e 12 [2] 25 14 [2] 39 13 [2] 25 3c }

  condition:
    any of them
}