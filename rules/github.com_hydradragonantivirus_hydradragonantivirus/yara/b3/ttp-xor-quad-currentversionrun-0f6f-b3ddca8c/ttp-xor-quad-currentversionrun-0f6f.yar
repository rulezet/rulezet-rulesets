rule TTP_XOR_QUAD_CurrentVersionRun_0f6f {
  strings:
    $key_0f6f = { 5c 00 [2] 78 0e [2] 53 22 [2] 7d 00 [2] 69 1b [2] 66 01 [2] 78 1c [2] 7a 1d [2] 61 1b [2] 7d 1c [2] 61 33 }

  condition:
    any of them
}