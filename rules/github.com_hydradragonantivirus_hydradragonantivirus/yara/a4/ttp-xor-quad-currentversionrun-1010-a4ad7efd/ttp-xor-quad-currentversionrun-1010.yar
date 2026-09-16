rule TTP_XOR_QUAD_CurrentVersionRun_1010 {
  strings:
    $key_1010 = { 43 7f [2] 67 71 [2] 4c 5d [2] 62 7f [2] 76 64 [2] 79 7e [2] 67 63 [2] 65 62 [2] 7e 64 [2] 62 63 [2] 7e 4c }

  condition:
    any of them
}