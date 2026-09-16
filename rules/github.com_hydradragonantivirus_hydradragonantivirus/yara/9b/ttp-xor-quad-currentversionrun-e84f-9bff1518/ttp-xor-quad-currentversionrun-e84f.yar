rule TTP_XOR_QUAD_CurrentVersionRun_e84f {
  strings:
    $key_e84f = { bb 20 [2] 9f 2e [2] b4 02 [2] 9a 20 [2] 8e 3b [2] 81 21 [2] 9f 3c [2] 9d 3d [2] 86 3b [2] 9a 3c [2] 86 13 }

  condition:
    any of them
}