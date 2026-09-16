rule TTP_XOR_QUAD_CurrentVersionRun_055f {
  strings:
    $key_055f = { 56 30 [2] 72 3e [2] 59 12 [2] 77 30 [2] 63 2b [2] 6c 31 [2] 72 2c [2] 70 2d [2] 6b 2b [2] 77 2c [2] 6b 03 }

  condition:
    any of them
}