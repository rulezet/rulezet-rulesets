rule TTP_XOR_QUAD_CurrentVersionRun_5a2f {
  strings:
    $key_5a2f = { 09 40 [2] 2d 4e [2] 06 62 [2] 28 40 [2] 3c 5b [2] 33 41 [2] 2d 5c [2] 2f 5d [2] 34 5b [2] 28 5c [2] 34 73 }

  condition:
    any of them
}