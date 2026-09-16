rule TTP_XOR_QUAD_CurrentVersionRun_214f {
  strings:
    $key_214f = { 72 20 [2] 56 2e [2] 7d 02 [2] 53 20 [2] 47 3b [2] 48 21 [2] 56 3c [2] 54 3d [2] 4f 3b [2] 53 3c [2] 4f 13 }

  condition:
    any of them
}