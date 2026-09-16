rule TTP_XOR_QUAD_CurrentVersionRun_305f {
  strings:
    $key_305f = { 63 30 [2] 47 3e [2] 6c 12 [2] 42 30 [2] 56 2b [2] 59 31 [2] 47 2c [2] 45 2d [2] 5e 2b [2] 42 2c [2] 5e 03 }

  condition:
    any of them
}