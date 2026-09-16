rule TTP_XOR_QUAD_CurrentVersionRun_655f {
  strings:
    $key_655f = { 36 30 [2] 12 3e [2] 39 12 [2] 17 30 [2] 03 2b [2] 0c 31 [2] 12 2c [2] 10 2d [2] 0b 2b [2] 17 2c [2] 0b 03 }

  condition:
    any of them
}