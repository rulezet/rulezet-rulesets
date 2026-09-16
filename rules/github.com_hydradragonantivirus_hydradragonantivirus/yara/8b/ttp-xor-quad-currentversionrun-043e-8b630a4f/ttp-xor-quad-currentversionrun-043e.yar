rule TTP_XOR_QUAD_CurrentVersionRun_043e {
  strings:
    $key_043e = { 57 51 [2] 73 5f [2] 58 73 [2] 76 51 [2] 62 4a [2] 6d 50 [2] 73 4d [2] 71 4c [2] 6a 4a [2] 76 4d [2] 6a 62 }

  condition:
    any of them
}