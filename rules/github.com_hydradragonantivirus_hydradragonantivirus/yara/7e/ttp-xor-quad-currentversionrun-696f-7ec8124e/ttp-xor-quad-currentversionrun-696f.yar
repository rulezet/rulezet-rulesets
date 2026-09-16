rule TTP_XOR_QUAD_CurrentVersionRun_696f {
  strings:
    $key_696f = { 3a 00 [2] 1e 0e [2] 35 22 [2] 1b 00 [2] 0f 1b [2] 00 01 [2] 1e 1c [2] 1c 1d [2] 07 1b [2] 1b 1c [2] 07 33 }

  condition:
    any of them
}