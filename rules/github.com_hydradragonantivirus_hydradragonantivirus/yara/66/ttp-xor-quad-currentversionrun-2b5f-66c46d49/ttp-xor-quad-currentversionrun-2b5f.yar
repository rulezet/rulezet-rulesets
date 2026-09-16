rule TTP_XOR_QUAD_CurrentVersionRun_2b5f {
  strings:
    $key_2b5f = { 78 30 [2] 5c 3e [2] 77 12 [2] 59 30 [2] 4d 2b [2] 42 31 [2] 5c 2c [2] 5e 2d [2] 45 2b [2] 59 2c [2] 45 03 }

  condition:
    any of them
}