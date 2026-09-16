rule TTP_XOR_QUAD_CurrentVersionRun_e34c {
  strings:
    $key_e34c = { b0 23 [2] 94 2d [2] bf 01 [2] 91 23 [2] 85 38 [2] 8a 22 [2] 94 3f [2] 96 3e [2] 8d 38 [2] 91 3f [2] 8d 10 }

  condition:
    any of them
}