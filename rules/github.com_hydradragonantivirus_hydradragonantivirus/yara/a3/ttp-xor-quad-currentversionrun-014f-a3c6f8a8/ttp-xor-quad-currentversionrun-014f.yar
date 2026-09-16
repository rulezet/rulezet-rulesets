rule TTP_XOR_QUAD_CurrentVersionRun_014f {
  strings:
    $key_014f = { 52 20 [2] 76 2e [2] 5d 02 [2] 73 20 [2] 67 3b [2] 68 21 [2] 76 3c [2] 74 3d [2] 6f 3b [2] 73 3c [2] 6f 13 }

  condition:
    any of them
}