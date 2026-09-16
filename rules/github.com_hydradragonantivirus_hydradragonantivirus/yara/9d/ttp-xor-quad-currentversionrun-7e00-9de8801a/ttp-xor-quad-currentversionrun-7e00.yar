rule TTP_XOR_QUAD_CurrentVersionRun_7e00 {
  strings:
    $key_7e00 = { 2d 6f [2] 09 61 [2] 22 4d [2] 0c 6f [2] 18 74 [2] 17 6e [2] 09 73 [2] 0b 72 [2] 10 74 [2] 0c 73 [2] 10 5c }

  condition:
    any of them
}