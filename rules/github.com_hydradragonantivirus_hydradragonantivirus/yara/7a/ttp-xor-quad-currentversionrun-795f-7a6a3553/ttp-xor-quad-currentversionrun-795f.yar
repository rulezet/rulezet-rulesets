rule TTP_XOR_QUAD_CurrentVersionRun_795f {
  strings:
    $key_795f = { 2a 30 [2] 0e 3e [2] 25 12 [2] 0b 30 [2] 1f 2b [2] 10 31 [2] 0e 2c [2] 0c 2d [2] 17 2b [2] 0b 2c [2] 17 03 }

  condition:
    any of them
}