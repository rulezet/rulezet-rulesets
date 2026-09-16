rule TTP_XOR_QUAD_CurrentVersionRun_040d {
  strings:
    $key_040d = { 57 62 [2] 73 6c [2] 58 40 [2] 76 62 [2] 62 79 [2] 6d 63 [2] 73 7e [2] 71 7f [2] 6a 79 [2] 76 7e [2] 6a 51 }

  condition:
    any of them
}