rule TTP_XOR_QUAD_CurrentVersionRun_041d {
  strings:
    $key_041d = { 57 72 [2] 73 7c [2] 58 50 [2] 76 72 [2] 62 69 [2] 6d 73 [2] 73 6e [2] 71 6f [2] 6a 69 [2] 76 6e [2] 6a 41 }

  condition:
    any of them
}