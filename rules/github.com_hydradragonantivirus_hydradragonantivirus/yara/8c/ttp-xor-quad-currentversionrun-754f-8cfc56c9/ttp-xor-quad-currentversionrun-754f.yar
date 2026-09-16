rule TTP_XOR_QUAD_CurrentVersionRun_754f {
  strings:
    $key_754f = { 26 20 [2] 02 2e [2] 29 02 [2] 07 20 [2] 13 3b [2] 1c 21 [2] 02 3c [2] 00 3d [2] 1b 3b [2] 07 3c [2] 1b 13 }

  condition:
    any of them
}