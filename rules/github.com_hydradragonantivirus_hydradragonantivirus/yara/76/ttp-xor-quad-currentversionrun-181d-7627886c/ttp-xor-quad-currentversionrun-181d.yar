rule TTP_XOR_QUAD_CurrentVersionRun_181d {
  strings:
    $key_181d = { 4b 72 [2] 6f 7c [2] 44 50 [2] 6a 72 [2] 7e 69 [2] 71 73 [2] 6f 6e [2] 6d 6f [2] 76 69 [2] 6a 6e [2] 76 41 }

  condition:
    any of them
}