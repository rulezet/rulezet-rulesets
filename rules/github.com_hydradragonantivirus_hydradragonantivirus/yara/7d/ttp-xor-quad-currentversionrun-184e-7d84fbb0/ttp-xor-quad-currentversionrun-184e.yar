rule TTP_XOR_QUAD_CurrentVersionRun_184e {
  strings:
    $key_184e = { 4b 21 [2] 6f 2f [2] 44 03 [2] 6a 21 [2] 7e 3a [2] 71 20 [2] 6f 3d [2] 6d 3c [2] 76 3a [2] 6a 3d [2] 76 12 }

  condition:
    any of them
}