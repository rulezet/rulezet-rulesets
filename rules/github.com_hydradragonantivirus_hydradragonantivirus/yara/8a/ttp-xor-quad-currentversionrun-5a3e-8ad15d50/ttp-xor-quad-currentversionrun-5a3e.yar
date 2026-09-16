rule TTP_XOR_QUAD_CurrentVersionRun_5a3e {
  strings:
    $key_5a3e = { 09 51 [2] 2d 5f [2] 06 73 [2] 28 51 [2] 3c 4a [2] 33 50 [2] 2d 4d [2] 2f 4c [2] 34 4a [2] 28 4d [2] 34 62 }

  condition:
    any of them
}