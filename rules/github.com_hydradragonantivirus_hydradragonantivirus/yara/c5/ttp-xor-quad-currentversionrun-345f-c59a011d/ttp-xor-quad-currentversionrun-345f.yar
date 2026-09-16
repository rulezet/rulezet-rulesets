rule TTP_XOR_QUAD_CurrentVersionRun_345f {
  strings:
    $key_345f = { 67 30 [2] 43 3e [2] 68 12 [2] 46 30 [2] 52 2b [2] 5d 31 [2] 43 2c [2] 41 2d [2] 5a 2b [2] 46 2c [2] 5a 03 }

  condition:
    any of them
}