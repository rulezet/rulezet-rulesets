rule TTP_XOR_QUAD_CurrentVersionRun_863b {
  strings:
    $key_863b = { d5 54 [2] f1 5a [2] da 76 [2] f4 54 [2] e0 4f [2] ef 55 [2] f1 48 [2] f3 49 [2] e8 4f [2] f4 48 [2] e8 67 }

  condition:
    any of them
}