rule TTP_XOR_QUAD_CurrentVersionRun_531e {
  strings:
    $key_531e = { 00 71 [2] 24 7f [2] 0f 53 [2] 21 71 [2] 35 6a [2] 3a 70 [2] 24 6d [2] 26 6c [2] 3d 6a [2] 21 6d [2] 3d 42 }

  condition:
    any of them
}