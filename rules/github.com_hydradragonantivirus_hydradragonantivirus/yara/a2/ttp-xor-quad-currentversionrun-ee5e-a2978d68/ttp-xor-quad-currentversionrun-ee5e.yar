rule TTP_XOR_QUAD_CurrentVersionRun_ee5e {
  strings:
    $key_ee5e = { bd 31 [2] 99 3f [2] b2 13 [2] 9c 31 [2] 88 2a [2] 87 30 [2] 99 2d [2] 9b 2c [2] 80 2a [2] 9c 2d [2] 80 02 }

  condition:
    any of them
}