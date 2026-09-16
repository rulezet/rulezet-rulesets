rule TTP_XOR_QUAD_CurrentVersionRun_b043 {
  strings:
    $key_b043 = { e3 2c [2] c7 22 [2] ec 0e [2] c2 2c [2] d6 37 [2] d9 2d [2] c7 30 [2] c5 31 [2] de 37 [2] c2 30 [2] de 1f }

  condition:
    any of them
}