rule TTP_XOR_QUAD_CurrentVersionRun_0a6f {
  strings:
    $key_0a6f = { 59 00 [2] 7d 0e [2] 56 22 [2] 78 00 [2] 6c 1b [2] 63 01 [2] 7d 1c [2] 7f 1d [2] 64 1b [2] 78 1c [2] 64 33 }

  condition:
    any of them
}