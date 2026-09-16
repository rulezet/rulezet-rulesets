rule TTP_XOR_QUAD_CurrentVersionRun_914e {
  strings:
    $key_914e = { c2 21 [2] e6 2f [2] cd 03 [2] e3 21 [2] f7 3a [2] f8 20 [2] e6 3d [2] e4 3c [2] ff 3a [2] e3 3d [2] ff 12 }

  condition:
    any of them
}