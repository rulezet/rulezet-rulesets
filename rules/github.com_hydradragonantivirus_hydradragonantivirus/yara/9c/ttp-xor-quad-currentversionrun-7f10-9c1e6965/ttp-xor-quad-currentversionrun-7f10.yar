rule TTP_XOR_QUAD_CurrentVersionRun_7f10 {
  strings:
    $key_7f10 = { 2c 7f [2] 08 71 [2] 23 5d [2] 0d 7f [2] 19 64 [2] 16 7e [2] 08 63 [2] 0a 62 [2] 11 64 [2] 0d 63 [2] 11 4c }

  condition:
    any of them
}