rule TTP_XOR_QUAD_CurrentVersionRun_6410 {
  strings:
    $key_6410 = { 37 7f [2] 13 71 [2] 38 5d [2] 16 7f [2] 02 64 [2] 0d 7e [2] 13 63 [2] 11 62 [2] 0a 64 [2] 16 63 [2] 0a 4c }

  condition:
    any of them
}