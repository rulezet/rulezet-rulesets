rule TTP_XOR_QUAD_CurrentVersionRun_ee61 {
  strings:
    $key_ee61 = { bd 0e [2] 99 00 [2] b2 2c [2] 9c 0e [2] 88 15 [2] 87 0f [2] 99 12 [2] 9b 13 [2] 80 15 [2] 9c 12 [2] 80 3d }

  condition:
    any of them
}