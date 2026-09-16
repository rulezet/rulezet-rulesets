rule TTP_XOR_QUAD_CurrentVersionRun_5f2f {
  strings:
    $key_5f2f = { 0c 40 [2] 28 4e [2] 03 62 [2] 2d 40 [2] 39 5b [2] 36 41 [2] 28 5c [2] 2a 5d [2] 31 5b [2] 2d 5c [2] 31 73 }

  condition:
    any of them
}