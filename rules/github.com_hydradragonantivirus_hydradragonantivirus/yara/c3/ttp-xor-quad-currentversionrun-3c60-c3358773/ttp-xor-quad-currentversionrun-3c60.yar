rule TTP_XOR_QUAD_CurrentVersionRun_3c60 {
  strings:
    $key_3c60 = { 6f 0f [2] 4b 01 [2] 60 2d [2] 4e 0f [2] 5a 14 [2] 55 0e [2] 4b 13 [2] 49 12 [2] 52 14 [2] 4e 13 [2] 52 3c }

  condition:
    any of them
}