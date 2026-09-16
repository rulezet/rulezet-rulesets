rule TTP_XOR_QUAD_CurrentVersionRun_ee70 {
  strings:
    $key_ee70 = { bd 1f [2] 99 11 [2] b2 3d [2] 9c 1f [2] 88 04 [2] 87 1e [2] 99 03 [2] 9b 02 [2] 80 04 [2] 9c 03 [2] 80 2c }

  condition:
    any of them
}