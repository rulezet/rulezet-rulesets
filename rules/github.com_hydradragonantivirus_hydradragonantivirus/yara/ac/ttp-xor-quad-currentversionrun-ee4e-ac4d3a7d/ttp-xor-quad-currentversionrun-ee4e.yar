rule TTP_XOR_QUAD_CurrentVersionRun_ee4e {
  strings:
    $key_ee4e = { bd 21 [2] 99 2f [2] b2 03 [2] 9c 21 [2] 88 3a [2] 87 20 [2] 99 3d [2] 9b 3c [2] 80 3a [2] 9c 3d [2] 80 12 }

  condition:
    any of them
}