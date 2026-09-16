rule TTP_XOR_QUAD_CurrentVersionRun_206f {
  strings:
    $key_206f = { 73 00 [2] 57 0e [2] 7c 22 [2] 52 00 [2] 46 1b [2] 49 01 [2] 57 1c [2] 55 1d [2] 4e 1b [2] 52 1c [2] 4e 33 }

  condition:
    any of them
}