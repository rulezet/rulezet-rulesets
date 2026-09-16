rule TTP_XOR_QUAD_CurrentVersionRun_245f {
  strings:
    $key_245f = { 77 30 [2] 53 3e [2] 78 12 [2] 56 30 [2] 42 2b [2] 4d 31 [2] 53 2c [2] 51 2d [2] 4a 2b [2] 56 2c [2] 4a 03 }

  condition:
    any of them
}