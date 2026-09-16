rule TTP_XOR_QUAD_CurrentVersionRun_819d {
  strings:
    $key_819d = { d2 f2 [2] f6 fc [2] dd d0 [2] f3 f2 [2] e7 e9 [2] e8 f3 [2] f6 ee [2] f4 ef [2] ef e9 [2] f3 ee [2] ef c1 }

  condition:
    any of them
}