rule TTP_XOR_QUAD_CurrentVersionRun_6d6f {
  strings:
    $key_6d6f = { 3e 00 [2] 1a 0e [2] 31 22 [2] 1f 00 [2] 0b 1b [2] 04 01 [2] 1a 1c [2] 18 1d [2] 03 1b [2] 1f 1c [2] 03 33 }

  condition:
    any of them
}