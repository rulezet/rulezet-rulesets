rule TTP_XOR_QUAD_CurrentVersionRun_046f {
  strings:
    $key_046f = { 57 00 [2] 73 0e [2] 58 22 [2] 76 00 [2] 62 1b [2] 6d 01 [2] 73 1c [2] 71 1d [2] 6a 1b [2] 76 1c [2] 6a 33 }

  condition:
    any of them
}