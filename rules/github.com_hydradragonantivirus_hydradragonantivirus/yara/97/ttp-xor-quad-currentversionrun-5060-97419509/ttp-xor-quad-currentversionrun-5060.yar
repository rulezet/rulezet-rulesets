rule TTP_XOR_QUAD_CurrentVersionRun_5060 {
  strings:
    $key_5060 = { 03 0f [2] 27 01 [2] 0c 2d [2] 22 0f [2] 36 14 [2] 39 0e [2] 27 13 [2] 25 12 [2] 3e 14 [2] 22 13 [2] 3e 3c }

  condition:
    any of them
}