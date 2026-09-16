rule TTP_XOR_QUAD_CurrentVersionRun_6b60 {
  strings:
    $key_6b60 = { 38 0f [2] 1c 01 [2] 37 2d [2] 19 0f [2] 0d 14 [2] 02 0e [2] 1c 13 [2] 1e 12 [2] 05 14 [2] 19 13 [2] 05 3c }

  condition:
    any of them
}