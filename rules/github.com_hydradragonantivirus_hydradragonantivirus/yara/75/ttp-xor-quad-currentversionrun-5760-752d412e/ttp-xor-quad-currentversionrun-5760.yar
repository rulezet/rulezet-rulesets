rule TTP_XOR_QUAD_CurrentVersionRun_5760 {
  strings:
    $key_5760 = { 04 0f [2] 20 01 [2] 0b 2d [2] 25 0f [2] 31 14 [2] 3e 0e [2] 20 13 [2] 22 12 [2] 39 14 [2] 25 13 [2] 39 3c }

  condition:
    any of them
}