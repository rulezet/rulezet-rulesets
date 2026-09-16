rule TTP_XOR_QUAD_CurrentVersionRun_7e5f {
  strings:
    $key_7e5f = { 2d 30 [2] 09 3e [2] 22 12 [2] 0c 30 [2] 18 2b [2] 17 31 [2] 09 2c [2] 0b 2d [2] 10 2b [2] 0c 2c [2] 10 03 }

  condition:
    any of them
}