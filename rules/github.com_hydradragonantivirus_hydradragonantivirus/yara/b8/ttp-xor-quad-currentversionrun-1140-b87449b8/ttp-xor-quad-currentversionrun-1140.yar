rule TTP_XOR_QUAD_CurrentVersionRun_1140 {
  strings:
    $key_1140 = { 42 2f [2] 66 21 [2] 4d 0d [2] 63 2f [2] 77 34 [2] 78 2e [2] 66 33 [2] 64 32 [2] 7f 34 [2] 63 33 [2] 7f 1c }

  condition:
    any of them
}