rule TTP_XOR_QUAD_CurrentVersionRun_1810 {
  strings:
    $key_1810 = { 4b 7f [2] 6f 71 [2] 44 5d [2] 6a 7f [2] 7e 64 [2] 71 7e [2] 6f 63 [2] 6d 62 [2] 76 64 [2] 6a 63 [2] 76 4c }

  condition:
    any of them
}