rule TTP_XOR_QUAD_CurrentVersionRun_e84c {
  strings:
    $key_e84c = { bb 23 [2] 9f 2d [2] b4 01 [2] 9a 23 [2] 8e 38 [2] 81 22 [2] 9f 3f [2] 9d 3e [2] 86 38 [2] 9a 3f [2] 86 10 }

  condition:
    any of them
}