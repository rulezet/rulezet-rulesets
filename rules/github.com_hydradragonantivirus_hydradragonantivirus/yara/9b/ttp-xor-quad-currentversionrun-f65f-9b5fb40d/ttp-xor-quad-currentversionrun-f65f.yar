rule TTP_XOR_QUAD_CurrentVersionRun_f65f {
  strings:
    $key_f65f = { a5 30 [2] 81 3e [2] aa 12 [2] 84 30 [2] 90 2b [2] 9f 31 [2] 81 2c [2] 83 2d [2] 98 2b [2] 84 2c [2] 98 03 }

  condition:
    any of them
}