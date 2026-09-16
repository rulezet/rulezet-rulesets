rule TTP_XOR_QUAD_CurrentVersionRun_4f2f {
  strings:
    $key_4f2f = { 1c 40 [2] 38 4e [2] 13 62 [2] 3d 40 [2] 29 5b [2] 26 41 [2] 38 5c [2] 3a 5d [2] 21 5b [2] 3d 5c [2] 21 73 }

  condition:
    any of them
}