rule TTP_XOR_QUAD_CurrentVersionRun_136f {
  strings:
    $key_136f = { 40 00 [2] 64 0e [2] 4f 22 [2] 61 00 [2] 75 1b [2] 7a 01 [2] 64 1c [2] 66 1d [2] 7d 1b [2] 61 1c [2] 7d 33 }

  condition:
    any of them
}