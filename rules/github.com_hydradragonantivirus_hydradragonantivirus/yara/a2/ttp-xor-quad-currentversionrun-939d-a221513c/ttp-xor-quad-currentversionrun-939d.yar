rule TTP_XOR_QUAD_CurrentVersionRun_939d {
  strings:
    $key_939d = { c0 f2 [2] e4 fc [2] cf d0 [2] e1 f2 [2] f5 e9 [2] fa f3 [2] e4 ee [2] e6 ef [2] fd e9 [2] e1 ee [2] fd c1 }

  condition:
    any of them
}