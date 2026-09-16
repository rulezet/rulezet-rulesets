rule TTP_XOR_QUAD_CurrentVersionRun_547e {
  strings:
    $key_547e = { 07 11 [2] 23 1f [2] 08 33 [2] 26 11 [2] 32 0a [2] 3d 10 [2] 23 0d [2] 21 0c [2] 3a 0a [2] 26 0d [2] 3a 22 }

  condition:
    any of them
}