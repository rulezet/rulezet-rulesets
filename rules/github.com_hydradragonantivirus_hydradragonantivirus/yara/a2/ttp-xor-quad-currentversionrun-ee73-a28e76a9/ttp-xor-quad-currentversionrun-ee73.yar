rule TTP_XOR_QUAD_CurrentVersionRun_ee73 {
  strings:
    $key_ee73 = { bd 1c [2] 99 12 [2] b2 3e [2] 9c 1c [2] 88 07 [2] 87 1d [2] 99 00 [2] 9b 01 [2] 80 07 [2] 9c 00 [2] 80 2f }

  condition:
    any of them
}