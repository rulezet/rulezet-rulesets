rule TTP_XOR_QUAD_CurrentVersionRun_4d4f {
  strings:
    $key_4d4f = { 1e 20 [2] 3a 2e [2] 11 02 [2] 3f 20 [2] 2b 3b [2] 24 21 [2] 3a 3c [2] 38 3d [2] 23 3b [2] 3f 3c [2] 23 13 }

  condition:
    any of them
}