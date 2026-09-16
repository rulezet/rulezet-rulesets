rule TTP_XOR_QUAD_CurrentVersionRun_584f {
  strings:
    $key_584f = { 0b 20 [2] 2f 2e [2] 04 02 [2] 2a 20 [2] 3e 3b [2] 31 21 [2] 2f 3c [2] 2d 3d [2] 36 3b [2] 2a 3c [2] 36 13 }

  condition:
    any of them
}