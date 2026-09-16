rule TTP_XOR_QUAD_CurrentVersionRun_e96f {
  strings:
    $key_e96f = { ba 00 [2] 9e 0e [2] b5 22 [2] 9b 00 [2] 8f 1b [2] 80 01 [2] 9e 1c [2] 9c 1d [2] 87 1b [2] 9b 1c [2] 87 33 }

  condition:
    any of them
}