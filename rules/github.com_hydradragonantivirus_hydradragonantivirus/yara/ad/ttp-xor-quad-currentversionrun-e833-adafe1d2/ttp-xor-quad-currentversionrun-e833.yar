rule TTP_XOR_QUAD_CurrentVersionRun_e833 {
  strings:
    $key_e833 = { bb 5c [2] 9f 52 [2] b4 7e [2] 9a 5c [2] 8e 47 [2] 81 5d [2] 9f 40 [2] 9d 41 [2] 86 47 [2] 9a 40 [2] 86 6f }

  condition:
    any of them
}