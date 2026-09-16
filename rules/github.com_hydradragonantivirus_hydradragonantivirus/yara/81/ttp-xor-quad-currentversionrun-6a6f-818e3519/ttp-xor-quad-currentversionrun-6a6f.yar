rule TTP_XOR_QUAD_CurrentVersionRun_6a6f {
  strings:
    $key_6a6f = { 39 00 [2] 1d 0e [2] 36 22 [2] 18 00 [2] 0c 1b [2] 03 01 [2] 1d 1c [2] 1f 1d [2] 04 1b [2] 18 1c [2] 04 33 }

  condition:
    any of them
}