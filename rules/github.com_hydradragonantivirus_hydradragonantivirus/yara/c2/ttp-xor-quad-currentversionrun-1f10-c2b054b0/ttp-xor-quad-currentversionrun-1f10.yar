rule TTP_XOR_QUAD_CurrentVersionRun_1f10 {
  strings:
    $key_1f10 = { 4c 7f [2] 68 71 [2] 43 5d [2] 6d 7f [2] 79 64 [2] 76 7e [2] 68 63 [2] 6a 62 [2] 71 64 [2] 6d 63 [2] 71 4c }

  condition:
    any of them
}