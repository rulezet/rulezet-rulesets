rule TTP_XOR_QUAD_CurrentVersionRun_195f {
  strings:
    $key_195f = { 4a 30 [2] 6e 3e [2] 45 12 [2] 6b 30 [2] 7f 2b [2] 70 31 [2] 6e 2c [2] 6c 2d [2] 77 2b [2] 6b 2c [2] 77 03 }

  condition:
    any of them
}