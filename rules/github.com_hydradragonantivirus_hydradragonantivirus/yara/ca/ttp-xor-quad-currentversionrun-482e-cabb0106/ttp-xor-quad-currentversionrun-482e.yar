rule TTP_XOR_QUAD_CurrentVersionRun_482e {
  strings:
    $key_482e = { 1b 41 [2] 3f 4f [2] 14 63 [2] 3a 41 [2] 2e 5a [2] 21 40 [2] 3f 5d [2] 3d 5c [2] 26 5a [2] 3a 5d [2] 26 72 }

  condition:
    any of them
}