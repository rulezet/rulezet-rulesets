rule TTP_XOR_QUAD_CurrentVersionRun_2e4e {
  strings:
    $key_2e4e = { 7d 21 [2] 59 2f [2] 72 03 [2] 5c 21 [2] 48 3a [2] 47 20 [2] 59 3d [2] 5b 3c [2] 40 3a [2] 5c 3d [2] 40 12 }

  condition:
    any of them
}