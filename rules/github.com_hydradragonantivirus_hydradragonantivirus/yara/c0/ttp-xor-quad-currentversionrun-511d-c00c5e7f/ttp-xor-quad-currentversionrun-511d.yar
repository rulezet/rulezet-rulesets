rule TTP_XOR_QUAD_CurrentVersionRun_511d {
  strings:
    $key_511d = { 02 72 [2] 26 7c [2] 0d 50 [2] 23 72 [2] 37 69 [2] 38 73 [2] 26 6e [2] 24 6f [2] 3f 69 [2] 23 6e [2] 3f 41 }

  condition:
    any of them
}