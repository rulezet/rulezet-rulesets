rule TTP_XOR_QUAD_CurrentVersionRun_ee43 {
  strings:
    $key_ee43 = { bd 2c [2] 99 22 [2] b2 0e [2] 9c 2c [2] 88 37 [2] 87 2d [2] 99 30 [2] 9b 31 [2] 80 37 [2] 9c 30 [2] 80 1f }

  condition:
    any of them
}