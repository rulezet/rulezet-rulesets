rule TTP_XOR_QUAD_CurrentVersionRun_ee4d {
  strings:
    $key_ee4d = { bd 22 [2] 99 2c [2] b2 00 [2] 9c 22 [2] 88 39 [2] 87 23 [2] 99 3e [2] 9b 3f [2] 80 39 [2] 9c 3e [2] 80 11 }

  condition:
    any of them
}