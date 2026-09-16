rule TTP_XOR_QUAD_CurrentVersionRun_f660 {
  strings:
    $key_f660 = { a5 0f [2] 81 01 [2] aa 2d [2] 84 0f [2] 90 14 [2] 9f 0e [2] 81 13 [2] 83 12 [2] 98 14 [2] 84 13 [2] 98 3c }

  condition:
    any of them
}