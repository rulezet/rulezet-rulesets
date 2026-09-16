rule TTP_XOR_QUAD_CurrentVersionRun_6f3e {
  strings:
    $key_6f3e = { 3c 51 [2] 18 5f [2] 33 73 [2] 1d 51 [2] 09 4a [2] 06 50 [2] 18 4d [2] 1a 4c [2] 01 4a [2] 1d 4d [2] 01 62 }

  condition:
    any of them
}