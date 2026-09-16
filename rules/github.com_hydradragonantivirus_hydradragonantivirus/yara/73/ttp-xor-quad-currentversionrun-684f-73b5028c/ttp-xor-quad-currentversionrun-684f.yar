rule TTP_XOR_QUAD_CurrentVersionRun_684f {
  strings:
    $key_684f = { 3b 20 [2] 1f 2e [2] 34 02 [2] 1a 20 [2] 0e 3b [2] 01 21 [2] 1f 3c [2] 1d 3d [2] 06 3b [2] 1a 3c [2] 06 13 }

  condition:
    any of them
}