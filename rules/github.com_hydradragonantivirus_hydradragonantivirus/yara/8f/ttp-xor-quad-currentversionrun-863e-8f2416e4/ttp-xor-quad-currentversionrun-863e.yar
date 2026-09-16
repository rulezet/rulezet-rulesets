rule TTP_XOR_QUAD_CurrentVersionRun_863e {
  strings:
    $key_863e = { d5 51 [2] f1 5f [2] da 73 [2] f4 51 [2] e0 4a [2] ef 50 [2] f1 4d [2] f3 4c [2] e8 4a [2] f4 4d [2] e8 62 }

  condition:
    any of them
}