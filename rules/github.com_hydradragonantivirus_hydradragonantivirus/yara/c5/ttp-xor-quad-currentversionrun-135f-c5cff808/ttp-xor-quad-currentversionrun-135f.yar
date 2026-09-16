rule TTP_XOR_QUAD_CurrentVersionRun_135f {
  strings:
    $key_135f = { 40 30 [2] 64 3e [2] 4f 12 [2] 61 30 [2] 75 2b [2] 7a 31 [2] 64 2c [2] 66 2d [2] 7d 2b [2] 61 2c [2] 7d 03 }

  condition:
    any of them
}