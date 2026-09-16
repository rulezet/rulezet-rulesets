rule TTP_XOR_QUAD_CurrentVersionRun_511c {
  strings:
    $key_511c = { 02 73 [2] 26 7d [2] 0d 51 [2] 23 73 [2] 37 68 [2] 38 72 [2] 26 6f [2] 24 6e [2] 3f 68 [2] 23 6f [2] 3f 40 }

  condition:
    any of them
}