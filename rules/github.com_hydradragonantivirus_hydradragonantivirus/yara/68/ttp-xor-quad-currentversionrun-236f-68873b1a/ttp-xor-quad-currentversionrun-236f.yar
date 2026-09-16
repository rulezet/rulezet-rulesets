rule TTP_XOR_QUAD_CurrentVersionRun_236f {
  strings:
    $key_236f = { 70 00 [2] 54 0e [2] 7f 22 [2] 51 00 [2] 45 1b [2] 4a 01 [2] 54 1c [2] 56 1d [2] 4d 1b [2] 51 1c [2] 4d 33 }

  condition:
    any of them
}