rule TTP_XOR_QUAD_CurrentVersionRun_146f {
  strings:
    $key_146f = { 47 00 [2] 63 0e [2] 48 22 [2] 66 00 [2] 72 1b [2] 7d 01 [2] 63 1c [2] 61 1d [2] 7a 1b [2] 66 1c [2] 7a 33 }

  condition:
    any of them
}