rule TTP_XOR_QUAD_CurrentVersionRun_385f {
  strings:
    $key_385f = { 6b 30 [2] 4f 3e [2] 64 12 [2] 4a 30 [2] 5e 2b [2] 51 31 [2] 4f 2c [2] 4d 2d [2] 56 2b [2] 4a 2c [2] 56 03 }

  condition:
    any of them
}