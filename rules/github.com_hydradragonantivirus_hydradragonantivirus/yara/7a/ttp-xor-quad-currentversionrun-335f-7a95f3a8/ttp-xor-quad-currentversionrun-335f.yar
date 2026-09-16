rule TTP_XOR_QUAD_CurrentVersionRun_335f {
  strings:
    $key_335f = { 60 30 [2] 44 3e [2] 6f 12 [2] 41 30 [2] 55 2b [2] 5a 31 [2] 44 2c [2] 46 2d [2] 5d 2b [2] 41 2c [2] 5d 03 }

  condition:
    any of them
}