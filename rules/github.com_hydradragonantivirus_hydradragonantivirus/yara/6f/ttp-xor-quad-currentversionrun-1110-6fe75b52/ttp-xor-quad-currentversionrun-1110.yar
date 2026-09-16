rule TTP_XOR_QUAD_CurrentVersionRun_1110 {
  strings:
    $key_1110 = { 42 7f [2] 66 71 [2] 4d 5d [2] 63 7f [2] 77 64 [2] 78 7e [2] 66 63 [2] 64 62 [2] 7f 64 [2] 63 63 [2] 7f 4c }

  condition:
    any of them
}