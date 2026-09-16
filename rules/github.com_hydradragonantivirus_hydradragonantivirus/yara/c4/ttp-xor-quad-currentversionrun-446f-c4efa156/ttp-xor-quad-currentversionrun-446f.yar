rule TTP_XOR_QUAD_CurrentVersionRun_446f {
  strings:
    $key_446f = { 17 00 [2] 33 0e [2] 18 22 [2] 36 00 [2] 22 1b [2] 2d 01 [2] 33 1c [2] 31 1d [2] 2a 1b [2] 36 1c [2] 2a 33 }

  condition:
    any of them
}