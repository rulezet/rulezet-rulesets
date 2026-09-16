rule TTP_XOR_QUAD_CurrentVersionRun_5f10 {
  strings:
    $key_5f10 = { 0c 7f [2] 28 71 [2] 03 5d [2] 2d 7f [2] 39 64 [2] 36 7e [2] 28 63 [2] 2a 62 [2] 31 64 [2] 2d 63 [2] 31 4c }

  condition:
    any of them
}