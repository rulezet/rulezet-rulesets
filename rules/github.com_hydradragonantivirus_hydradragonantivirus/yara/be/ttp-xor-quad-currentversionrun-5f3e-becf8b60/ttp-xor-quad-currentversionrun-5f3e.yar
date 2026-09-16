rule TTP_XOR_QUAD_CurrentVersionRun_5f3e {
  strings:
    $key_5f3e = { 0c 51 [2] 28 5f [2] 03 73 [2] 2d 51 [2] 39 4a [2] 36 50 [2] 28 4d [2] 2a 4c [2] 31 4a [2] 2d 4d [2] 31 62 }

  condition:
    any of them
}