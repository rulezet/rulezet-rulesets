rule TTP_XOR_QUAD_CurrentVersionRun_e84d {
  strings:
    $key_e84d = { bb 22 [2] 9f 2c [2] b4 00 [2] 9a 22 [2] 8e 39 [2] 81 23 [2] 9f 3e [2] 9d 3f [2] 86 39 [2] 9a 3e [2] 86 11 }

  condition:
    any of them
}