rule TTP_XOR_QUAD_CurrentVersionRun_e54e {
  strings:
    $key_e54e = { b6 21 [2] 92 2f [2] b9 03 [2] 97 21 [2] 83 3a [2] 8c 20 [2] 92 3d [2] 90 3c [2] 8b 3a [2] 97 3d [2] 8b 12 }

  condition:
    any of them
}