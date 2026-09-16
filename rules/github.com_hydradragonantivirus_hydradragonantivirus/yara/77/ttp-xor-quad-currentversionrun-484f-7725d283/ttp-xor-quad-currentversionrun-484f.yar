rule TTP_XOR_QUAD_CurrentVersionRun_484f {
  strings:
    $key_484f = { 1b 20 [2] 3f 2e [2] 14 02 [2] 3a 20 [2] 2e 3b [2] 21 21 [2] 3f 3c [2] 3d 3d [2] 26 3b [2] 3a 3c [2] 26 13 }

  condition:
    any of them
}