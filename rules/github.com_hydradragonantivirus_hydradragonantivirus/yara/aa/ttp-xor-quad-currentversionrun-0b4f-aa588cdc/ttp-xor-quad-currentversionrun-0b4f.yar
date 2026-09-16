rule TTP_XOR_QUAD_CurrentVersionRun_0b4f {
  strings:
    $key_0b4f = { 58 20 [2] 7c 2e [2] 57 02 [2] 79 20 [2] 6d 3b [2] 62 21 [2] 7c 3c [2] 7e 3d [2] 65 3b [2] 79 3c [2] 65 13 }

  condition:
    any of them
}