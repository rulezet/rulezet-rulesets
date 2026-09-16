rule TTP_XOR_QUAD_CurrentVersionRun_863f {
  strings:
    $key_863f = { d5 50 [2] f1 5e [2] da 72 [2] f4 50 [2] e0 4b [2] ef 51 [2] f1 4c [2] f3 4d [2] e8 4b [2] f4 4c [2] e8 63 }

  condition:
    any of them
}