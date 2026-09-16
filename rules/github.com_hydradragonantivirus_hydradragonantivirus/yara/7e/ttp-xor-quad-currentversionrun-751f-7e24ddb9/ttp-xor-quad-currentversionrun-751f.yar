rule TTP_XOR_QUAD_CurrentVersionRun_751f {
  strings:
    $key_751f = { 26 70 [2] 02 7e [2] 29 52 [2] 07 70 [2] 13 6b [2] 1c 71 [2] 02 6c [2] 00 6d [2] 1b 6b [2] 07 6c [2] 1b 43 }

  condition:
    any of them
}