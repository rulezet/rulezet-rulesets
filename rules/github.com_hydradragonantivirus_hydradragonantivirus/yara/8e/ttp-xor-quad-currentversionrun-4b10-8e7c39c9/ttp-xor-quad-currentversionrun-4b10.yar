rule TTP_XOR_QUAD_CurrentVersionRun_4b10 {
  strings:
    $key_4b10 = { 18 7f [2] 3c 71 [2] 17 5d [2] 39 7f [2] 2d 64 [2] 22 7e [2] 3c 63 [2] 3e 62 [2] 25 64 [2] 39 63 [2] 25 4c }

  condition:
    any of them
}