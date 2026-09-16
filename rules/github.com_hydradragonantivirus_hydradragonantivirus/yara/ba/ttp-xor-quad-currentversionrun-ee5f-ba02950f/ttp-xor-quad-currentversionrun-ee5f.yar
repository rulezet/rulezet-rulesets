rule TTP_XOR_QUAD_CurrentVersionRun_ee5f {
  strings:
    $key_ee5f = { bd 30 [2] 99 3e [2] b2 12 [2] 9c 30 [2] 88 2b [2] 87 31 [2] 99 2c [2] 9b 2d [2] 80 2b [2] 9c 2c [2] 80 03 }

  condition:
    any of them
}