rule TTP_XOR_QUAD_CurrentVersionRun_0410 {
  strings:
    $key_0410 = { 57 7f [2] 73 71 [2] 58 5d [2] 76 7f [2] 62 64 [2] 6d 7e [2] 73 63 [2] 71 62 [2] 6a 64 [2] 76 63 [2] 6a 4c }

  condition:
    any of them
}